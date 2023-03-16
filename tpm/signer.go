package tpm

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"

	"go.step.sm/crypto/tpm/storage"
)

// signer implements crypto.Signer backed by a TPM key.
type signer struct {
	tpm    *TPM
	key    Key
	public crypto.PublicKey
}

// Public returns the signers public key.
func (s *signer) Public() crypto.PublicKey {
	return s.public
}

// Sign implements crypto.Signer. It is backed by a TPM key.
// The TPM key is loaded lazily, meaning that every call to Sign()
// will reload the TPM key to be used.
func (s *signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx := context.Background()
	if err := s.tpm.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer s.tpm.Close(ctx)

	loadedKey, err := s.tpm.attestTPM.LoadKey(s.key.data)
	if err != nil {
		return nil, err
	}
	defer loadedKey.Close()

	priv, err := loadedKey.Private(s.public)
	if err != nil {
		return nil, fmt.Errorf("failed getting TPM private key %q: %w", s.key.name, err)
	}

	var signer crypto.Signer
	var ok bool
	if signer, ok = priv.(crypto.Signer); !ok {
		return nil, fmt.Errorf("failed getting TPM private key %q as crypto.Signer", s.key.name)
	}

	return signer.Sign(rand, digest, opts)
}

// GetSigner returns a crypto.Signer for a TPM Key identified by `name`.
func (t *TPM) GetSigner(ctx context.Context, name string) (crypto.Signer, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	key, err := t.store.GetKey(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed getting signer for key %q: %w", name, ErrNotFound)
		}
		return nil, err
	}

	loadedKey, err := t.attestTPM.LoadKey(key.Data)
	if err != nil {
		return nil, err
	}
	defer loadedKey.Close()

	priv, err := loadedKey.Private(loadedKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed getting TPM private key %q: %w", name, err)
	}

	if _, ok := priv.(crypto.Signer); !ok {
		return nil, fmt.Errorf("failed getting TPM private key %q as crypto.Signer", name)
	}

	return &signer{
		tpm:    t,
		key:    Key{name: name, data: key.Data, attestedBy: key.AttestedBy, createdAt: key.CreatedAt, tpm: t},
		public: loadedKey.Public(),
	}, nil
}
