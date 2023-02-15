package tpm

import (
	"context"
	"crypto/rand"
	"fmt"
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

func (t *TPM) Close(ctx context.Context) {
	t.lock.Unlock()
}

func processName(name string) (string, error) {
	if name == "" {
		// TODO: decouple the TPM key name from the name recorded in the storage? This might
		// make it easier to work with the key names as a user; the TPM key name would be abstracted
		// away. The key name in the storage can be different from the key stored with the key (which,
		// to be far, isn't even used on Linux TPMs)
		nameHex := make([]byte, 5)
		if n, err := rand.Read(nameHex); err != nil || n != len(nameHex) {
			return "", fmt.Errorf("failed reading from CSPRNG: %w", err)
		}
		name = fmt.Sprintf("%x", nameHex)
	}

	return name, nil
}
