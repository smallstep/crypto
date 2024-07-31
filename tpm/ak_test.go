package tpm

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/x509util"
)

func TestAK_MarshalJSON(t *testing.T) {
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
	cr.Subject.CommonName = "testkey"

	csr, err := cr.GetCertificateRequest()
	require.NoError(t, err)

	cert, err := ca.SignCSR(csr)
	require.NoError(t, err)

	ak := &AK{
		name:      "ak1",
		data:      []byte{1, 2, 3, 4},
		createdAt: time.Time{},
	}

	data, err := json.Marshal(ak)
	require.NoError(t, err)

	m := map[string]any{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	require.Equal(t, m["name"], ak.name)
	require.Equal(t, m["data"], base64.StdEncoding.EncodeToString(ak.data))
	require.Equal(t, m["chain"], nil)
	require.Equal(t, m["createdAt"], ak.createdAt.Format("2006-01-02T15:04:05Z"))

	ak = &AK{
		name:      "ak2",
		data:      []byte{1, 2, 3, 4},
		chain:     []*x509.Certificate{cert, ca.Intermediate},
		createdAt: time.Time{},
	}

	data, err = json.Marshal(ak)
	require.NoError(t, err)

	m = map[string]any{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	require.Equal(t, m["name"], ak.name)
	require.Equal(t, m["data"], base64.StdEncoding.EncodeToString(ak.data))
	require.Equal(t, m["chain"], []any{base64.StdEncoding.EncodeToString(cert.Raw), base64.StdEncoding.EncodeToString(ca.Intermediate.Raw)})
	require.Equal(t, m["createdAt"], ak.createdAt.Format("2006-01-02T15:04:05Z"))
}
