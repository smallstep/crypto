//go:build go1.27

package pemutil

import (
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/mldsa"
)

func TestSerializeParse_MLDSA(t *testing.T) {
	for _, crv := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(crv, func(t *testing.T) {
			priv, err := keyutil.GenerateKey("MLDSA", crv, 0)
			require.NoError(t, err)
			signer := priv.(*mldsa.PrivateKey)
			pub := signer.Public()

			// Private key round-trip (PKCS#8, "PRIVATE KEY").
			block, err := Serialize(priv)
			require.NoError(t, err)
			assert.Equal(t, "PRIVATE KEY", block.Type)
			parsedPriv, err := Parse(pem.EncodeToMemory(block))
			require.NoError(t, err)
			assert.True(t, keyutil.Equal(priv, parsedPriv))

			// Public key round-trip (PKIX, "PUBLIC KEY").
			block, err = Serialize(pub)
			require.NoError(t, err)
			assert.Equal(t, "PUBLIC KEY", block.Type)
			parsedPub, err := Parse(pem.EncodeToMemory(block))
			require.NoError(t, err)
			assert.True(t, keyutil.Equal(pub, parsedPub))

			// Encrypted private key round-trip.
			password := []byte("supersecret")
			block, err = Serialize(priv, WithPassword(password))
			require.NoError(t, err)
			assert.Equal(t, "ENCRYPTED PRIVATE KEY", block.Type)
			decryptedPriv, err := Parse(pem.EncodeToMemory(block), WithPassword(password))
			require.NoError(t, err)
			assert.True(t, keyutil.Equal(priv, decryptedPriv))
		})
	}
}
