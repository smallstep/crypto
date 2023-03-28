package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/x509util"
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

func TestEK_MarshalJSON(t *testing.T) {

	ca, err := minica.New(
		minica.WithGetSignerFunc(
			func() (crypto.Signer, error) {
				return keyutil.GenerateSigner("RSA", "", 2048)
			},
		),
	)
	require.NoError(t, err)

	signer, err := keyutil.GenerateSigner("RSA", "", 2048)
	require.NoError(t, err)

	cr, err := x509util.NewCertificateRequest(signer)
	require.NoError(t, err)
	cr.Subject.CommonName = "testek"

	csr, err := cr.GetCertificateRequest()
	require.NoError(t, err)

	cert, err := ca.SignCSR(csr)
	require.NoError(t, err)

	ek := &EK{
		public:         signer.Public(),
		certificate:    cert,
		certificateURL: "https://certificate.example.com",
	}

	data, err := json.Marshal(ek)
	require.NoError(t, err)

	m := map[string]interface{}{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	keyID, err := generateKeyID(signer.Public())
	require.NoError(t, err)
	fp := "sha256:" + base64.StdEncoding.EncodeToString(keyID)

	require.Equal(t, m["type"], "RSA 2048")
	require.Equal(t, m["fingerprint"], fp)
	require.Equal(t, m["der"], base64.StdEncoding.EncodeToString(cert.Raw))
	require.Equal(t, m["url"], "https://certificate.example.com")
}
