package storage

import (
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/x509util"
)

func TestAK_MarshalUnmarshal(t *testing.T) {

	ca, err := minica.New()
	require.NoError(t, err)

	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)

	cr, err := x509util.NewCertificateRequest(signer)
	require.NoError(t, err)
	cr.Subject.CommonName = "testak"

	csr, err := cr.GetCertificateRequest()
	require.NoError(t, err)

	cert, err := ca.SignCSR(csr)
	require.NoError(t, err)

	ak := &AK{
		Name:      "ak1",
		Data:      []byte{1, 2, 3, 4},
		Chain:     []*x509.Certificate{cert, ca.Intermediate},
		CreatedAt: time.Time{},
	}

	data, err := json.Marshal(ak)
	require.NoError(t, err)

	var rak = &AK{}
	err = json.Unmarshal(data, rak)
	require.NoError(t, err)
	require.Equal(t, ak, rak)
}

func TestKey_MarshalUnmarshal(t *testing.T) {

	ca, err := minica.New()
	require.NoError(t, err)

	signer, err := keyutil.GenerateDefaultSigner()
	require.NoError(t, err)

	cr, err := x509util.NewCertificateRequest(signer)
	require.NoError(t, err)
	cr.Subject.CommonName = "testkey"

	csr, err := cr.GetCertificateRequest()
	require.NoError(t, err)

	cert, err := ca.SignCSR(csr)
	require.NoError(t, err)

	key := &Key{
		Name:       "key1",
		Data:       []byte{1, 2, 3, 4},
		AttestedBy: "ak1",
		Chain:      []*x509.Certificate{cert, ca.Intermediate},
		CreatedAt:  time.Time{},
	}

	data, err := json.Marshal(key)
	require.NoError(t, err)

	var rkey = &Key{}
	err = json.Unmarshal(data, rkey)
	require.NoError(t, err)
	require.Equal(t, key, rkey)
}
