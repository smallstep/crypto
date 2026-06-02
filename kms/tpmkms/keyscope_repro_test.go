//go:build tpmsimulator

package tpmkms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
)

// TestTPMKMS_CreateKey_machineScopedAKAttestation reproduces the agent's
// enrollment path: create a machine-scoped AK via tpmkms (ak=true;
// key-scope=machine), then attest a machine-scoped device key by it. Before
// the fix, the AK was created with the user-default scope (CreateAK ignored
// key-scope), so AttestKey's symmetric check rejected the machine-scoped
// attested key with "MachineKey=true does not match AK ... (MachineKey=false)".
func TestTPMKMS_CreateKey_machineScopedAKAttestation(t *testing.T) {
	k := &TPMKMS{tpm: newSimulatedTPM(t)}

	akResp, err := k.CreateKey(&apiv1.CreateKeyRequest{
		Name: "tpmkms:name=ak1;ak=true;key-scope=machine",
	})
	require.NoError(t, err)
	// The returned AK URI must preserve the machine scope for re-opens.
	assert.Equal(t, "tpmkms:name=ak1;ak=true;key-scope=machine", akResp.Name)

	// This is the exact URI the agent builds in attester.Attest; before the
	// fix it failed with a scope mismatch.
	_, err = k.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "tpmkms:name=key1;attest-by=ak1;key-scope=machine;store-location=machine",
		SignatureAlgorithm: apiv1.SHA256WithRSA,
		Bits:               1024,
	})
	require.NoError(t, err)

	// A user-scoped attested key by the machine AK must still be rejected
	// (the symmetric check works in both directions).
	_, err = k.CreateKey(&apiv1.CreateKeyRequest{
		Name:               "tpmkms:name=key2;attest-by=ak1",
		SignatureAlgorithm: apiv1.SHA256WithRSA,
		Bits:               1024,
	})
	require.Error(t, err)
}
