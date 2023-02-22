package tpm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_keyType(t *testing.T) {
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.Equal(t, "RSA 2048", keyType(r.Public()))

	e, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	require.Equal(t, "ECDSA P-256", keyType(e.Public()))

	// break the ECDSA key
	e.Curve.Params().BitSize = 1234
	require.Equal(t, "unexpected ECDSA size: 1234", keyType(e.Public()))
}
