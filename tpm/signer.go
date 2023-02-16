package tpm

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-attestation/attest"
	"go.step.sm/crypto/tpm/storage"
)

// signer implements crypto.Signer backed by a TPM key
type signer struct {
	tpm    *TPM
	key    Key
	public crypto.PublicKey
}

func (s *signer) Public() crypto.PublicKey {
	return s.public
}

func (s *signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx := context.Background()
	if err := s.tpm.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer s.tpm.Close(ctx)

	at, err := attest.OpenTPM(s.tpm.attestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	loadedKey, err := at.LoadKey(s.key.data)
	if err != nil {
		return nil, err
	}
	defer loadedKey.Close()

	priv, err := loadedKey.Private(s.public)
	if err != nil {
		return nil, err
	}

	var signer crypto.Signer
	var ok bool
	if signer, ok = priv.(crypto.Signer); !ok {
		return nil, fmt.Errorf("failed getting TPM private key %q as crypto.Signer", s.key.name)
	}

	return signer.Sign(rand, digest, opts)
}

// GetSigner returns a crypto.Signer for a TPM key identified by name.
func (t *TPM) GetSigner(ctx context.Context, name string) (crypto.Signer, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	at, err := attest.OpenTPM(t.attestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	key, err := t.store.GetKey(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed getting signer for key %q: %w", name, ErrNotFound)
		}
		return nil, err
	}

	loadedKey, err := at.LoadKey(key.Data)
	if err != nil {
		return nil, err
	}
	defer loadedKey.Close()

	return &signer{
		tpm:    t,
		key:    Key{name: name, data: key.Data, attestedBy: key.AttestedBy, createdAt: key.CreatedAt, tpm: t},
		public: loadedKey.Public(),
	}, nil
}
