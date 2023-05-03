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

func TestKey_MarshalJSON(t *testing.T) {

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

	key := &Key{
		name:       "key1",
		data:       []byte{1, 2, 3, 4},
		attestedBy: "ak1",
		createdAt:  time.Time{},
	}

	data, err := json.Marshal(key)
	require.NoError(t, err)

	m := map[string]interface{}{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	require.Equal(t, m["name"], key.name)
	require.Equal(t, m["data"], base64.StdEncoding.EncodeToString(key.data))
	require.Equal(t, m["attestedBy"], key.attestedBy)
	require.Equal(t, m["chain"], nil)
	require.Equal(t, m["createdAt"], key.createdAt.Format("2006-01-02T15:04:05Z"))

	key = &Key{
		name:       "key2",
		data:       []byte{1, 2, 3, 4},
		attestedBy: "ak1",
		chain:      []*x509.Certificate{cert, ca.Intermediate},
		createdAt:  time.Time{},
	}

	data, err = json.Marshal(key)
	require.NoError(t, err)

	m = map[string]interface{}{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	require.Equal(t, m["name"], key.name)
	require.Equal(t, m["data"], base64.StdEncoding.EncodeToString(key.data))
	require.Equal(t, m["attestedBy"], key.attestedBy)
	require.Equal(t, m["chain"], []interface{}{base64.StdEncoding.EncodeToString(cert.Raw), base64.StdEncoding.EncodeToString(ca.Intermediate.Raw)})
	require.Equal(t, m["createdAt"], key.createdAt.Format("2006-01-02T15:04:05Z"))
}
