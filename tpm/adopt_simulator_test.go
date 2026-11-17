//go:build tpmsimulator

package tpm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTPM_AdoptKey_unsupportedWhereKeysHaveNoName(t *testing.T) {
	// The simulator stands in for a Linux TPM, which keeps keys as blobs in
	// the record and never under a name, so there is nothing to adopt.
	tpm := newSimulatedTPM(t)
	pub := mustECDSAPublic(t)

	_, err := tpm.AdoptKey(context.Background(), "endpoint", AdoptKeyConfig{Public: pub})
	require.ErrorIs(t, err, ErrAdoptUnsupported)

	_, err = tpm.CreateAK(context.Background(), "ak")
	require.NoError(t, err)
	_, err = tpm.AdoptAttestedKey(context.Background(), "ak", "endpoint", AdoptAttestedKeyConfig{
		Public: pub, QualifyingData: []byte{1, 2, 3},
	})
	require.ErrorIs(t, err, ErrAdoptUnsupported)

	_, err = tpm.GetKey(context.Background(), "endpoint")
	require.ErrorIs(t, err, ErrNotFound, "nothing is recorded")
}

func TestTPM_AdoptKey_refusesARecordedName(t *testing.T) {
	tpm := newSimulatedTPM(t)
	_, err := tpm.CreateKey(context.Background(), "endpoint", CreateKeyConfig{Algorithm: "ECDSA", Size: 256})
	require.NoError(t, err)

	_, err = tpm.AdoptKey(context.Background(), "endpoint", AdoptKeyConfig{Public: mustECDSAPublic(t)})
	require.ErrorIs(t, err, ErrExists)
}

func TestTPM_AdoptAttestedKey_needsTheAK(t *testing.T) {
	tpm := newSimulatedTPM(t)

	_, err := tpm.AdoptAttestedKey(context.Background(), "missing-ak", "endpoint", AdoptAttestedKeyConfig{
		Public: mustECDSAPublic(t),
	})
	require.ErrorIs(t, err, ErrNotFound)
}

func mustECDSAPublic(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &k.PublicKey
}
