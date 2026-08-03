//go:build tpmsimulator

package tpm

import (
	"context"
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/smallstep/go-attestation/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// akVerifyOpts builds the options needed to verify a certification signed by
// ak, mirroring what a relying party does with the AK's public key.
func akVerifyOpts(t *testing.T, ak *AK) attest.VerifyOpts {
	t.Helper()

	params, err := ak.AttestationParameters(context.Background())
	require.NoError(t, err)

	pub, err := tpm2.DecodePublic(params.Public)
	require.NoError(t, err)

	hash, err := pub.RSAParameters.Sign.Hash.Hash()
	require.NoError(t, err)

	return attest.VerifyOpts{
		Public: &rsa.PublicKey{
			E: int(pub.RSAParameters.Exponent()),
			N: pub.RSAParameters.Modulus(),
		},
		Hash: hash,
	}
}

// extraData returns the qualifying data bound into a certification.
func extraData(t *testing.T, params attest.CertificationParameters) []byte {
	t.Helper()

	att, err := tpm2.DecodeAttestationData(params.CreateAttestation)
	require.NoError(t, err)
	require.Equal(t, tpm2.TagAttestCertify, att.Type)

	return att.ExtraData
}

// TestKey_Recertify covers the property the change exists for: one persisted
// key can produce a valid certification against a nonce chosen after the key
// was created. Without it, binding a new nonce requires a new key.
func TestKey_Recertify(t *testing.T) {
	ctx := context.Background()
	tpm := newSimulatedTPM(t)

	ak, err := tpm.CreateAK(ctx, "ak")
	require.NoError(t, err)

	firstNonce := []byte("first-order-key-authorization")
	key, err := tpm.AttestKey(ctx, "ak", "key", AttestKeyConfig{
		Algorithm:      "RSA",
		Size:           2048,
		QualifyingData: firstNonce,
	})
	require.NoError(t, err)

	verifyOpts := akVerifyOpts(t, ak)

	// The stored certification carries the nonce the key was created with.
	stored, err := key.CertificationParameters(ctx)
	require.NoError(t, err)
	require.NoError(t, stored.Verify(verifyOpts))
	assert.Equal(t, firstNonce, extraData(t, stored))

	// Re-certifying binds a different nonce to the same key.
	secondNonce := []byte("second-order-key-authorization")
	fresh, err := key.Recertify(ctx, secondNonce)
	require.NoError(t, err)

	assert.Equal(t, secondNonce, extraData(t, fresh))
	assert.NotEqual(t, stored.CreateAttestation, fresh.CreateAttestation)
	assert.NotEqual(t, stored.CreateSignature, fresh.CreateSignature)

	// It is still the same key, and the fresh statement satisfies every check
	// a relying party makes — this is what lets the credential persist.
	assert.Equal(t, stored.Public, fresh.Public)
	require.NoError(t, fresh.Verify(verifyOpts))

	// Re-certifying does not disturb the stored certification.
	reread, err := key.CertificationParameters(ctx)
	require.NoError(t, err)
	assert.Equal(t, firstNonce, extraData(t, reread))

	// The key remains usable for signing.
	signer, err := key.Signer(ctx)
	require.NoError(t, err)
	digest := []byte("01234567890123456789012345678901")
	_, err = signer.Sign(nil, digest, crypto.SHA256)
	require.NoError(t, err)
}

// TestKey_Recertify_notAttested guards the precondition: a key with no AK has
// nothing to certify it, and must say so rather than fail obscurely.
func TestKey_Recertify_notAttested(t *testing.T) {
	ctx := context.Background()
	tpm := newSimulatedTPM(t)

	key, err := tpm.CreateKey(ctx, "unattested", CreateKeyConfig{
		Algorithm: "RSA",
		Size:      2048,
	})
	require.NoError(t, err)

	_, err = key.Recertify(ctx, []byte("nonce"))
	assert.EqualError(t, err, `key "unattested" was not attested`)
}
