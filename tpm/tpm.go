package tpm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/smallstep/go-attestation/attest"

	"go.step.sm/crypto/tpm/internal/open"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

// TPM models a Trusted Platform Module. It provides an abstraction
// over the google/go-tpm and google/go-attestation packages, allowing
// functionalities of these packages to be performed in a uniform manner.
// Besides that, it provides a transparent method for persisting TPM
// objects, so that referencing and using these is simplified.
type TPM struct {
	deviceName   string
	attestConfig *attest.OpenConfig
	attestTPM    *attest.TPM
	rwc          io.ReadWriteCloser
	lock         sync.RWMutex
	store        storage.TPMStore
	simulator    simulator.Simulator
	downloader   *downloader
	info         *Info
	eks          []*EK
}

// NewTPMOption is used to provide options when instantiating a new
// instance of TPM.
type NewTPMOption func(t *TPM) error

// WithDeviceName is used to provide the `name` or path to the TPM
// device.
func WithDeviceName(name string) NewTPMOption {
	return func(t *TPM) error {
		if name != "" {
			t.deviceName = name
		}
		return nil
	}
}

// WithStore is used to set the TPMStore implementation to use for
// persisting TPM objects, including AKs and Keys.
func WithStore(store storage.TPMStore) NewTPMOption {
	return func(t *TPM) error {
		if store == nil {
			store = storage.BlackHole() // prevent nil storage; no persistence
		}

		t.store = store
		return nil
	}
}

// WithDisableDownload disables EK certificates from being downloaded
// from online hosts.
func WithDisableDownload() NewTPMOption {
	return func(t *TPM) error {
		t.downloader.enabled = false
		return nil
	}
}

// WithSimulator is used to configure a TPM simulator implementation
// that simulates TPM operations instead of interacting with an actual
// TPM.
func WithSimulator(sim simulator.Simulator) NewTPMOption {
	return func(t *TPM) error {
		t.simulator = sim
		return nil
	}
}

// New creates a new TPM instance. It takes `opts` to configure
// the instance.
func New(opts ...NewTPMOption) (*TPM, error) {
	tpm := &TPM{
		attestConfig: &attest.OpenConfig{TPMVersion: attest.TPMVersion20},                      // default configuration for TPM attestation use cases
		store:        storage.BlackHole(),                                                      // default storage doesn't persist anything // TODO(hs): make this in-memory storage instead?
		downloader:   &downloader{enabled: true, maxDownloads: 10, client: http.DefaultClient}, // EK certificate download (if required) is enabled by default
	}

	for _, o := range opts {
		if err := o(tpm); err != nil {
			return nil, err
		}
	}

	return tpm, nil
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

	// if a simulator was set, use it as the backing TPM device.
	// The simulator is currently only used for testing.
	if t.simulator != nil {
		if t.attestTPM == nil {
			at, err := attest.OpenTPM(&attest.OpenConfig{
				TPMVersion:     attest.TPMVersion20,
				CommandChannel: t.simulator,
			})
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
		err := t.attestTPM.Close()
		t.attestTPM = nil
		if err != nil {
			return fmt.Errorf("failed closing attest.TPM: %w", err)
		}
	}

	// clean up the go-tpm rwc
	if t.rwc != nil {
		err := t.rwc.Close()
		t.rwc = nil
		if err != nil {
			return fmt.Errorf("failed closing rwc: %w", err)
		}
	}

	return nil
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
