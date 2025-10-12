package tpm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/smallstep/go-attestation/attest"

	"go.step.sm/crypto/kms/uri"
	closer "go.step.sm/crypto/tpm/internal/close"
	"go.step.sm/crypto/tpm/internal/mssim"
	"go.step.sm/crypto/tpm/internal/open"
	"go.step.sm/crypto/tpm/internal/socket"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

// TPM models a Trusted Platform Module. It provides an abstraction
// over the google/go-tpm and google/go-attestation packages, allowing
// functionalities of these packages to be performed in a uniform manner.
// Besides that, it provides a transparent method for persisting TPM
// objects, so that referencing and using these is simplified.
type TPM struct {
	deviceName             string
	attestConfig           *attest.OpenConfig
	attestTPM              *attest.TPM
	rwc                    io.ReadWriteCloser
	lock                   sync.RWMutex
	store                  storage.TPMStore
	simulator              simulator.Simulator
	commandChannel         CommandChannel
	downloader             *downloader
	options                *options
	initCommandChannelOnce sync.Once
	info                   *Info
	caps                   *Capabilities
	eks                    []*EK
}

// NewTPMOption is used to provide options when instantiating a new
// instance of TPM.
type NewTPMOption func(o *options) error

// WithDeviceName is used to provide the `name` or path to the TPM
// device.
func WithDeviceName(name string) NewTPMOption {
	return func(o *options) error {
		if name != "" {
			o.deviceName = name
		}
		return nil
	}
}

// WithStore is used to set the TPMStore implementation to use for
// persisting TPM objects, including AKs and Keys.
func WithStore(store storage.TPMStore) NewTPMOption {
	return func(o *options) error {
		if store == nil {
			store = storage.BlackHole() // prevent nil storage; no persistence
		}
		o.store = store
		return nil
	}
}

// WithDisableDownload disables EK certificates from being downloaded
// from online hosts.
func WithDisableDownload() NewTPMOption {
	return func(o *options) error {
		o.downloader.enabled = false
		return nil
	}
}

// WithSimulator is used to configure a TPM simulator implementation
// that simulates TPM operations instead of interacting with an actual
// TPM.
func WithSimulator(sim simulator.Simulator) NewTPMOption {
	return func(o *options) error {
		o.simulator = sim
		return nil
	}
}

type CommandChannel attest.CommandChannelTPM20

// WithCommandChannel is used to configure a [CommandChannel] as the
// interface to interact with instead of with an actual TPM.
func WithCommandChannel(commandChannel CommandChannel) NewTPMOption {
	return func(o *options) error {
		o.commandChannel = commandChannel
		return nil
	}
}

// WithCapabilities explicitly sets the capabilities rather
// than acquiring them from the TPM directly. The primary use
// for this option is to ease testing different TPM capabilities.
//
// # Experimental
//
// Notice: This option is EXPERIMENTAL and may be changed or removed
// in a later release.
func WithCapabilities(caps *Capabilities) NewTPMOption {
	return func(o *options) error {
		o.caps = caps
		return nil
	}
}

type options struct {
	deviceName     string
	attestConfig   *attest.OpenConfig
	simulator      simulator.Simulator
	commandChannel CommandChannel
	store          storage.TPMStore
	downloader     *downloader
	caps           *Capabilities
}

func (o *options) validate() error {
	if o.simulator != nil && o.commandChannel != nil {
		return errors.New("WithSimulator and WithCommandChannel options are mutually exclusive")
	}
	return nil
}

// New creates a new TPM instance. It takes `opts` to configure
// the instance. By default it uses a blackhole storage, meaning
// that there's no actual persistence. Some operations require
// an actual persistence mechanism, and will return an error if
// none is configured.
func New(opts ...NewTPMOption) (*TPM, error) {
	tpmOptions := options{
		attestConfig: &attest.OpenConfig{TPMVersion: attest.TPMVersion20},                      // default configuration for TPM attestation use cases
		store:        storage.BlackHole(),                                                      // default storage doesn't persist anything // TODO(hs): make this in-memory storage instead?
		downloader:   &downloader{enabled: true, maxDownloads: 10, client: http.DefaultClient}, // EK certificate download (if required) is enabled by default
	}
	for _, o := range opts {
		if err := o(&tpmOptions); err != nil {
			return nil, err
		}
	}
	if err := tpmOptions.validate(); err != nil {
		return nil, fmt.Errorf("invalid TPM options provided: %w", err)
	}

	return &TPM{
		deviceName:     tpmOptions.deviceName,
		attestConfig:   tpmOptions.attestConfig,
		store:          tpmOptions.store,
		downloader:     tpmOptions.downloader,
		simulator:      tpmOptions.simulator,
		commandChannel: tpmOptions.commandChannel,
		caps:           tpmOptions.caps,
		options:        &tpmOptions,
	}, nil
}

// Open readies the TPM for usage and marks it as being
// in use. This makes using the instance safe for
// concurrent use.
func (t *TPM) open(ctx context.Context) (err error) {
	// prevent opening the TPM multiple times if Open is called
	// within the package multiple times.
	if isInternalCall(ctx) {
		return
	}

	// lock the TPM instance; it's in use now
	t.lock.Lock()
	defer func() {
		if err != nil {
			t.lock.Unlock()
		}
	}()

	if err := t.store.Load(); err != nil { // TODO(hs): load this once? Or abstract this away.
		return fmt.Errorf("failed loading from TPM storage: %w", err)
	}

	// initialize the command channel
	t.initCommandChannelOnce.Do(func() {
		err = t.initializeCommandChannel()
	})
	if err != nil {
		return fmt.Errorf("failed initializing command channel: %w", err)
	}

	// if a simulator was set, use it as the backing TPM device.
	// The simulator is currently only used for testing.
	if t.simulator != nil {
		if t.attestTPM == nil {
			at, err := attest.OpenTPM(t.attestConfig)
			if err != nil {
				return fmt.Errorf("failed opening attest.TPM: %w", err)
			}
			t.attestTPM = at
		}
		t.rwc = t.simulator
	} else {
		// TODO(hs): when an internal call to open is performed, but when
		// switching the "TPM implementation" to use between the two types,
		// there's a possibility of a nil pointer exception. At the moment,
		// the only "go-tpm" call is for GetRandom(), but this could change
		// in the future.
		if isGoTPMCall(ctx) {
			rwc, err := open.TPM(t.deviceName)
			if err != nil {
				return fmt.Errorf("failed opening TPM: %w", err)
			}
			t.rwc = rwc
		} else {
			// TODO(hs): attest.OpenTPM doesn't currently take into account the
			// device name provided. This doesn't seem to be an available option
			// to filter on currently?
			at, err := attest.OpenTPM(t.attestConfig)
			if err != nil {
				return fmt.Errorf("failed opening TPM: %w", err)
			}
			t.attestTPM = at
		}
	}

	return nil
}

// initializeCommandChannel initializes the TPM's command channel based on
// configuration provided when creating the TPM instance. The method is
// primarily used to be able to use a TPM simulator in lieu of a real TPM
// being available or when the real TPM should not be used. There's a special
// case for a TPM exposed using a UNIX socket, which also is used primarily
// for interacting with a TPM simulator.
func (t *TPM) initializeCommandChannel() error {
	// return early with the complete `attestConfig` set if
	// command channel was provided before.
	if t.commandChannel != nil {
		t.attestConfig = &attest.OpenConfig{
			TPMVersion:     t.options.attestConfig.TPMVersion,
			CommandChannel: t.commandChannel,
		}
		return nil
	}

	if t.options.simulator != nil {
		t.commandChannel = t.simulator
	}

	if t.options.commandChannel != nil {
		t.commandChannel = t.options.commandChannel
	}

	if t.commandChannel == nil {
		switch {
		case strings.HasPrefix(t.deviceName, "mssim:"):
			// if the TPM device name looks like a URI that starts with "mssim:", try
			// using a TCP connection to the TPM using the Microsoft PTM simulator TCTI.
			msSimCommandChannel, err := tryMsSimCommandChannel(t.deviceName)
			if err != nil {
				return fmt.Errorf("invalid Microsoft TPM Simulator device name %q: %w", t.deviceName, err)
			}
			t.commandChannel = msSimCommandChannel
		default:
			// finally, check if the device name points to a UNIX socket, and use that
			// as the command channel, if available.
			if socketCommandChannel, err := trySocketCommandChannel(t.deviceName); err != nil {
				switch {
				case errors.Is(err, socket.ErrNotSupported):
					// don't try to use socket command channel if not supported. No need to return
					// an error, because the code should still rely on the default TPM command channel.
				case !errors.Is(err, socket.ErrNotAvailable):
					return err
				}
			} else {
				t.commandChannel = socketCommandChannel
			}
		}
	}

	// update `attestConfig` with the command channel, so that it is used whenever
	// attestation operations are being performed. Note that the command channel can
	// still be nil. It simply won't be used (wrapped) by `go-attestation` in that case.
	t.attestConfig = &attest.OpenConfig{
		TPMVersion:     t.options.attestConfig.TPMVersion,
		CommandChannel: t.commandChannel,
	}

	return nil
}

// trySocketCommandChannel tries to establish connections to a TPM using
// a UNIX socket.
func trySocketCommandChannel(path string) (*socket.CommandChannelWithoutMeasurementLog, error) {
	rwc, err := socket.New(path)
	if err != nil {
		return nil, err
	}
	return &socket.CommandChannelWithoutMeasurementLog{ReadWriteCloser: rwc}, nil
}

// tryMsSimCommandChannel tries to establish connections to a TPM using the
// Microsoft TPM Simulator TCTI.
func tryMsSimCommandChannel(rawuri string) (*mssim.CommandChannelWithoutMeasurementLog, error) {
	u, err := uri.ParseWithScheme("mssim", rawuri)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", rawuri, err)
	}
	rwc, err := mssim.New(u)
	if err != nil {
		return nil, err
	}
	return &mssim.CommandChannelWithoutMeasurementLog{ReadWriteCloser: rwc}, nil
}

// Close closes the TPM instance, cleaning up resources and
// marking it ready to be use again.
func (t *TPM) close(ctx context.Context) error {
	// prevent closing the TPM multiple times if Open is called
	// within the package multiple times.
	if isInternalCall(ctx) {
		return nil
	}

	// if simulation is enabled, closing the TPM simulator must not
	// happen, because re-opening it will result in a different instance,
	// resulting in issues when running multiple test operations in
	// sequence. Closing a simulator has to be done in the calling code,
	// meaning it has to happen at the end of the test.
	if t.simulator != nil {
		t.lock.Unlock()
		return nil // return early, so that simulator remains usable.
	}

	// mark the TPM as ready to be used again when returning
	defer t.lock.Unlock()

	// clean up the attest.TPM
	if t.attestTPM != nil {
		defer func() { t.attestTPM = nil }()
		if err := closer.AttestTPM(t.attestTPM, t.attestConfig); err != nil {
			return fmt.Errorf("failed closing attest.TPM: %w", err)
		}
	}

	// clean up the go-tpm rwc
	if t.rwc != nil {
		defer func() { t.rwc = nil }()
		if err := closer.RWC(t.rwc); err != nil {
			return fmt.Errorf("failed closing rwc: %w", err)
		}
	}

	return nil
}

func (t *TPM) Available() (err error) {
	_, err = t.Info(context.Background())
	return
}

type validatableConfig interface {
	Validate() error
}

func (t *TPM) validate(config validatableConfig) error {
	return config.Validate()
}

// closeTPM closes TPM `t`. It must be called as a deferred function
// every time TPM `t` is opened. If `ep` is nil and closing the TPM
// returned an error, `ep` will be pointed to the latter. In practice
// this  means that errors originating from main-line logic will have
// precedence over errors returned from closing the TPM.
func closeTPM(ctx context.Context, t *TPM, ep *error) { //nolint:gocritic // pointer to error required to be able to point it to an error
	if err := t.close(ctx); err != nil && *ep == nil {
		*ep = err
	}
}
