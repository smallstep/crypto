//go:build go1.27

package mldsa

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupported(t *testing.T) {
	assert.True(t, Supported)
}

func TestGenerateSigner(t *testing.T) {
	for _, name := range []string{MLDSA44Name, MLDSA65Name, MLDSA87Name} {
		t.Run(name, func(t *testing.T) {
			signer, err := GenerateSigner(name)
			require.NoError(t, err)

			priv, ok := signer.(*PrivateKey)
			require.True(t, ok)

			pub, ok := signer.Public().(*PublicKey)
			require.True(t, ok)
			assert.Equal(t, name, pub.Parameters().String())
			assert.True(t, priv.PublicKey().Equal(pub))

			message := []byte("the quick brown fox jumps over the lazy dog")

			// Default signing and verification.
			sig, err := signer.Sign(rand.Reader, message, &Options{})
			require.NoError(t, err)
			require.NoError(t, Verify(pub, message, sig, &Options{}))

			// A signature must not verify against a different message.
			require.Error(t, Verify(pub, []byte("other"), sig, &Options{}))

			// Signing/verifying with a context.
			ctxOpts := &Options{Context: "test-context"}
			sig, err = signer.Sign(rand.Reader, message, ctxOpts)
			require.NoError(t, err)
			require.NoError(t, Verify(pub, message, sig, ctxOpts))
			// The context must match on verification.
			require.Error(t, Verify(pub, message, sig, &Options{}))
		})
	}
}

func TestNewPrivateKeyFromSeed(t *testing.T) {
	seed := make([]byte, PrivateKeySize)
	for i := range seed {
		seed[i] = byte(i)
	}

	// Deriving a key from the same seed twice yields the same key.
	a, err := NewPrivateKey(MLDSA65(), seed)
	require.NoError(t, err)
	b, err := NewPrivateKey(MLDSA65(), seed)
	require.NoError(t, err)
	assert.True(t, a.Equal(b))
}

func TestOptionsHashFunc(t *testing.T) {
	var opts crypto.SignerOpts = &Options{}
	assert.Equal(t, crypto.Hash(0), opts.HashFunc())
}
