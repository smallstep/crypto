package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

type incomparablePublicKey struct{}

func TestExpectedPublic(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		key     string
		pub     crypto.PublicKey
		wantErr bool
	}{
		{"a name and a comparable key", "endpoint", &k.PublicKey, false},
		{"no name, so nothing to find the key by", "", &k.PublicKey, true},
		{"no public key, so nothing shows the key is the one meant", "endpoint", nil, true},
		{"a public key that cannot be compared", "endpoint", incomparablePublicKey{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := expectedPublic(tc.key, tc.pub)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
