//go:build go1.27

package x509util

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/mldsa"
)

func TestSignatureAlgorithm_MLDSA_JSON(t *testing.T) {
	tests := []struct {
		name string
		want x509.SignatureAlgorithm
	}{
		{"ML-DSA-44", x509.MLDSA44},
		{"ML-DSA-65", x509.MLDSA65},
		{"ML-DSA-87", x509.MLDSA87},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sa SignatureAlgorithm
			require.NoError(t, json.Unmarshal([]byte(`"`+tt.name+`"`), &sa))
			assert.Equal(t, tt.want, x509.SignatureAlgorithm(sa))

			b, err := json.Marshal(sa)
			require.NoError(t, err)
			assert.JSONEq(t, `"`+tt.name+`"`, string(b))
		})
	}
}

func TestCreateCertificate_MLDSA(t *testing.T) {
	priv, err := keyutil.GenerateKey("MLDSA", "ML-DSA-65", 0)
	require.NoError(t, err)
	signer := priv.(*mldsa.PrivateKey)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ml-dsa test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		// SignatureAlgorithm left unset: inferred from the ML-DSA signer.
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	assert.Equal(t, x509.MLDSA65, cert.SignatureAlgorithm)
	assert.Equal(t, x509.MLDSA, cert.PublicKeyAlgorithm)
	require.IsType(t, &mldsa.PublicKey{}, cert.PublicKey)

	// The certificate is self-signed and must verify against itself.
	require.NoError(t, cert.CheckSignatureFrom(cert))
}
