package tpm

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-attestation/attest"

	"go.step.sm/crypto/tpm/internal/open"
	"go.step.sm/crypto/tpm/simulator"
	"go.step.sm/crypto/tpm/storage"
)

type TPM struct {
	deviceName      string
	attestConfig    *attest.OpenConfig
	attestTPM       *attest.TPM
	rwc             io.ReadWriteCloser
	enableSimulator bool
	lock            sync.RWMutex
	store           storage.TPMStore
}

type NewTPMOption func(t *TPM) error

func WithDeviceName(name string) NewTPMOption {
	return func(t *TPM) error {
		t.deviceName = name
		return nil
	}
}

func WithStore(store storage.TPMStore) NewTPMOption {
	return func(t *TPM) error {
		if store == nil {
			store = storage.BlackHole() // prevent nil storage; no persistence
		}

		t.store = store
		return nil
	}
}

func New(opts ...NewTPMOption) (*TPM, error) {
	tpm := &TPM{
		attestConfig: &attest.OpenConfig{TPMVersion: attest.TPMVersion20}, // default configuration for TPM attestation use cases
		store:        storage.BlackHole(),                                 // default storage doesn't persist anything
	}

	for _, o := range opts {
		if err := o(tpm); err != nil {
			return nil, err
		}
	}

	return tpm, nil
}

func (t *TPM) Open(ctx context.Context) error {
	// prevent opening the TPM multiple times if Open is called
	// within the package multiple times.
	if isInternalCall(ctx) {
		return nil
	}

	t.lock.Lock()

	if err := t.store.Load(); err != nil { // TODO: load this once
		return err
	}

	if t.enableSimulator {
		sim := simulator.New()
		if err := sim.Open(ctx); err != nil {
			return fmt.Errorf("failed opening TPM simulator: %w", err)
		}
		at, err := attest.OpenTPM(&attest.OpenConfig{
			TPMVersion:     attest.TPMVersion20,
			CommandChannel: sim,
		})
		if err != nil {
			return fmt.Errorf("failed opening attest.TPM: %w", err)
		}
		t.attestTPM = at
		t.rwc = sim
	} else {
		if isGoTPMCall(ctx) {
			rwc, err := open.TPM(t.deviceName)
			if err != nil {
				return fmt.Errorf("failed opening TPM: %w", err)
			}
			t.rwc = rwc
		} else {
			at, err := attest.OpenTPM(t.attestConfig)
			if err != nil {
				return fmt.Errorf("failed opening TPM: %w", err)
			}
			t.attestTPM = at
		}
	}

	return nil
}

func (t *TPM) Close(ctx context.Context) {
	// prevent closing the TPM multiple times if Open is called
	// within the package multiple times.
	if isInternalCall(ctx) {
		return
	}

	if t.attestTPM != nil {
		err := t.attestTPM.Close()
		_ = err // TODO: handle error correctly (in defer)
		t.attestTPM = nil
	}

	if t.rwc != nil {
		err := t.rwc.Close()
		_ = err // TODO: handle error correctly (in defer)
		t.rwc = nil
	}

	t.lock.Unlock()
}
