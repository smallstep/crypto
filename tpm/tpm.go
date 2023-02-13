package tpm

import (
	"context"
	"sync"

	"github.com/google/go-attestation/attest"

	"go.step.sm/crypto/tpm/storage"
)

type TPM struct {
	deviceName   string
	attestConfig *attest.OpenConfig
	lock         sync.RWMutex
	store        storage.TPMStore
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

	t.lock.Lock()

	if err := t.store.Load(); err != nil { // TODO: load this once
		return err
	}

	return nil
}

func (t *TPM) Close(ctx context.Context, shouldPersist bool) error {
	if shouldPersist {
		if err := t.store.Persist(); err != nil {
			return err
		}
	}

	t.lock.Unlock()

	return nil
}
