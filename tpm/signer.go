package tpm

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"go.step.sm/crypto/tpm/tss2"
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
	if err = s.tpm.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, s.tpm, &err)

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
func (t *TPM) GetSigner(ctx context.Context, name string) (csigner crypto.Signer, err error) {
	if err = t.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	key, err := t.store.GetKey(name)
	if err != nil {
		return nil, fmt.Errorf("failed getting signer for key %q: %w", name, err)
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

	csigner = &signer{
		tpm:    t,
		key:    Key{name: name, data: key.Data, attestedBy: key.AttestedBy, createdAt: key.CreatedAt, tpm: t},
		public: loadedKey.Public(),
	}

	return
}

// tss2Signer is a wrapper on top of [*tss2.Signer] that opens and closes the
// tpm on each sign call.
type tss2Signer struct {
	*tss2.Signer
	tpm *TPM
}

func (s *tss2Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	ctx := context.Background()
	if err = s.tpm.open(goTPMCall(ctx)); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, s.tpm, &err)
	s.SetCommandChannel(s.tpm.rwc)
	signature, err = s.Signer.Sign(rand, digest, opts)
	return
}

// CreateTSS2Signer returns a crypto.Signer using the given [TPM] and [tss2.TPMKey].
func CreateTSS2Signer(ctx context.Context, t *TPM, key *tss2.TPMKey) (csigner crypto.Signer, err error) {
	if err := t.open(goTPMCall(ctx)); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	s, err := tss2.CreateSigner(t.rwc, key)
	if err != nil {
		return nil, fmt.Errorf("failed creating TSS2 signer: %w", err)
	}

	csigner = &tss2Signer{
		Signer: s,
		tpm:    t,
	}

	return
}
