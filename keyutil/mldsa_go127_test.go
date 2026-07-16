//go:build go1.27

package keyutil

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/mldsa"
)

func TestGenerateKey_MLDSA(t *testing.T) {
	for _, crv := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(crv, func(t *testing.T) {
			priv, err := GenerateKey("MLDSA", crv, 0)
			require.NoError(t, err)

			signer, ok := priv.(*mldsa.PrivateKey)
			require.True(t, ok)

			// PublicKey extracts the public key from the private key.
			pub, err := PublicKey(priv)
			require.NoError(t, err)
			require.IsType(t, &mldsa.PublicKey{}, pub)

			// PublicKey passes through an existing public key.
			same, err := PublicKey(pub)
			require.NoError(t, err)
			assert.True(t, Equal(pub, same))

			// Equal matches / mismatches.
			assert.True(t, Equal(pub, signer.Public()))
			assert.True(t, Equal(priv, priv))
			other, err := GenerateKey("MLDSA", crv, 0)
			require.NoError(t, err)
			assert.False(t, Equal(pub, other.(crypto.Signer).Public()))

			// ExtractKey passes ML-DSA keys through unchanged.
			gotPriv, err := ExtractKey(priv)
			require.NoError(t, err)
			assert.Equal(t, priv, gotPriv)
			gotPub, err := ExtractKey(pub)
			require.NoError(t, err)
			assert.Equal(t, pub, gotPub)

			// VerifyPair succeeds for a matching pair.
			require.NoError(t, VerifyPair(pub, priv))
		})
	}
}

func TestGenerateKey_MLDSA_invalid(t *testing.T) {
	_, err := GenerateKey("MLDSA", "ML-DSA-99", 0)
	require.Error(t, err)
}
