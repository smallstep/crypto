//go:build tpmsimulator

package tpmkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
	tpmp "go.step.sm/crypto/tpm"
)

func TestTPMKMS_AdoptKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	t.Run("unsupported where keys have no name", func(t *testing.T) {
		// The simulator stands in for a Linux TPM, which keeps keys as
		// blobs in the record, so there is nothing persisted to adopt.
		k := &TPMKMS{tpm: newSimulatedTPM(t, withAK("ak1"))}
		for _, name := range []string{"tpmkms:name=key1", "tpmkms:name=key1;attest-by=ak1;qualifying-data=61626364"} {
			_, err := k.AdoptKey(&apiv1.AdoptKeyRequest{Name: name, PublicKey: &priv.PublicKey})
			assert.ErrorIs(t, err, tpmp.ErrAdoptUnsupported, name)
		}
	})

	t.Run("a recorded key is already there", func(t *testing.T) {
		k := &TPMKMS{tpm: newSimulatedTPM(t)}
		_, err := k.CreateKey(&apiv1.CreateKeyRequest{Name: "tpmkms:name=key1", SignatureAlgorithm: apiv1.ECDSAWithSHA256})
		require.NoError(t, err)

		_, err = k.AdoptKey(&apiv1.AdoptKeyRequest{Name: "tpmkms:name=key1", PublicKey: &priv.PublicKey})
		assert.ErrorAs(t, err, &apiv1.AlreadyExistsError{})
	})

	t.Run("invalid requests", func(t *testing.T) {
		k := &TPMKMS{tpm: newSimulatedTPM(t)}
		for _, req := range []*apiv1.AdoptKeyRequest{
			{PublicKey: &priv.PublicKey},
			{Name: "tpmkms:name=ak1;ak=true", PublicKey: &priv.PublicKey},
			{Name: "tpmkms:name=key1"},
		} {
			_, err := k.AdoptKey(req)
			assert.Error(t, err, req.Name)
		}
	})
}

func TestTPMKMS_CreateKey_overwriteIsInertWhereKeysHaveNoName(t *testing.T) {
	k := &TPMKMS{tpm: newSimulatedTPM(t)}
	resp, err := k.CreateKey(&apiv1.CreateKeyRequest{
		Name: "tpmkms:name=key1;overwrite=true", SignatureAlgorithm: apiv1.ECDSAWithSHA256,
	})
	require.NoError(t, err)
	assert.Equal(t, "tpmkms:name=key1", resp.Name, "overwrite is a creation option, not part of the key's URI")
}
