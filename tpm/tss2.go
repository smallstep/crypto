package tpm

import (
	"context"

	"go.step.sm/crypto/tpm/tss2"
)

const (
	// Defined in "Registry of reserved TPM 2.0 handles and localities",
	// and checked on a glinux machine. This is the default parent handle
	// used by go-tpm and go-attestation, and thus also the default handle
	// set when marshaling to the TSS2 format.
	commonSrkEquivalentHandle = 0x81000001
)

// ToTSS2 gets the public and private blobs and returns a [*tss2.TPMKey].
func (ak *AK) ToTSS2(ctx context.Context) (*tss2.TPMKey, error) {
	blobs, err := ak.Blobs(ctx)
	if err != nil {
		return nil, err
	}
	return tss2.New(
		blobs.public,
		blobs.private,
		tss2.WithParent(commonSrkEquivalentHandle), // default parent used by go-tpm/go-attestation
	), nil
}

// ToTSS2 gets the public and private blobs and returns a [*tss2.TPMKey].
func (k *Key) ToTSS2(ctx context.Context) (*tss2.TPMKey, error) {
	blobs, err := k.Blobs(ctx)
	if err != nil {
		return nil, err
	}
	return tss2.New(
		blobs.public,
		blobs.private,
		tss2.WithParent(commonSrkEquivalentHandle), // default parent used by go-tpm/go-attestation
	), nil
}
