package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignerOpts(t *testing.T) {
	p256 := &ecdsa.PublicKey{Curve: elliptic.P256()}
	p384 := &ecdsa.PublicKey{Curve: elliptic.P384()}
	p521 := &ecdsa.PublicKey{Curve: elliptic.P521()}
	digest := func(n int) []byte {
		return bytes.Repeat([]byte{0xff}, n)
	}
	padded := func(n, size int) []byte {
		return append(make([]byte, size-n), digest(n)...)
	}

	tests := []struct {
		name       string
		key        crypto.PublicKey
		digest     []byte
		opts       crypto.SignerOpts
		wantDigest []byte
		wantOpts   crypto.SignerOpts
		wantErr    bool
	}{
		{"ok opts", &rsa.PublicKey{}, digest(32), crypto.SHA384, digest(32), crypto.SHA384, false},
		{"ok P-256", p256, digest(32), nil, digest(32), crypto.SHA256, false},
		{"ok P-256 truncated", p256, digest(64), nil, digest(32), crypto.SHA256, false},
		{"ok P-256 padded", p256, digest(20), nil, padded(20, 32), crypto.SHA256, false},
		{"ok P-256 one byte", p256, digest(1), nil, padded(1, 32), crypto.SHA256, false},
		{"ok P-256 message", p256, digest(200), nil, digest(32), crypto.SHA256, false},
		{"ok P-384", p384, digest(48), nil, digest(48), crypto.SHA384, false},
		{"ok P-384 truncated", p384, digest(66), nil, digest(48), crypto.SHA384, false},
		{"ok P-384 padded", p384, digest(28), nil, padded(28, 48), crypto.SHA384, false},
		{"ok P-521", p521, digest(64), nil, digest(64), crypto.SHA512, false},
		{"ok P-521 padded", p521, digest(16), nil, padded(16, 64), crypto.SHA512, false},
		{"ok ed25519", ed25519.PublicKey{}, []byte("message"), nil, []byte("message"), crypto.Hash(0), false},
		{"fail P-521 too long", p521, digest(65), nil, nil, nil, true},
		{"fail empty digest", p256, nil, nil, nil, nil, true},
		{"fail no curve", &ecdsa.PublicKey{}, digest(32), nil, nil, nil, true},
		{"fail unsupported curve", &ecdsa.PublicKey{Curve: elliptic.P224()}, digest(28), nil, nil, nil, true},
		{"fail rsa", &rsa.PublicKey{}, digest(32), nil, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDigest, gotOpts, err := SignerOpts(tt.key, tt.digest, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantDigest, gotDigest)
			assert.Equal(t, tt.wantOpts, gotOpts)
		})
	}
}

// TestSignerOpts_verify checks that, for every digest length from 1 to 80
// bytes, a signature over the digest SignerOpts returns verifies against the
// original digest, as it would if ecdsa.PrivateKey.Sign had signed it with nil
// opts. P-521 with a digest longer than 64 bytes must fail.
func TestSignerOpts_verify(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
		for n := 1; n <= 80; n++ {
			t.Run(fmt.Sprintf("%s/%d", curve.Params().Name, n), func(t *testing.T) {
				original := make([]byte, n)
				_, err := rand.Read(original)
				require.NoError(t, err)
				// Make the leftmost byte non-zero, so truncating or padding
				// the wrong end of the digest changes the signed value.
				original[0] |= 0x80

				digest, _, err := SignerOpts(key.Public(), original, nil)
				if curve == elliptic.P521() && n > 64 {
					assert.Error(t, err)
					return
				}
				require.NoError(t, err)
				sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
				require.NoError(t, err)
				assert.True(t, ecdsa.VerifyASN1(&key.PublicKey, original, sig))
			})
		}
	}
}
