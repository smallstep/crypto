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

	m := map[string]interface{}{}
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

	m = map[string]interface{}{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)

	require.Equal(t, m["name"], ak.name)
	require.Equal(t, m["data"], base64.StdEncoding.EncodeToString(ak.data))
	require.Equal(t, m["chain"], []interface{}{base64.StdEncoding.EncodeToString(cert.Raw), base64.StdEncoding.EncodeToString(ca.Intermediate.Raw)})
	require.Equal(t, m["createdAt"], ak.createdAt.Format("2006-01-02T15:04:05Z"))
}

// func TestAK_HasValidPermanentIdentifier(t *testing.T) {
// 	ca, err := minica.New(
// 		minica.WithGetSignerFunc(
// 			func() (crypto.Signer, error) {
// 				return keyutil.GenerateSigner("RSA", "", 2048)
// 			},
// 		),
// 	)
// 	require.NoError(t, err)

// 	signer, err := keyutil.GenerateSigner("RSA", "", 2048)
// 	require.NoError(t, err)

// 	cr, err := x509util.NewCertificateRequest(signer)
// 	require.NoError(t, err)
// 	cr.Subject.CommonName = "testkey"

// 	cr.Extensions = []x509util.Extension{

// 	}

// 	// ok permanent identifier template
// 	permanentIdentifierTemplate := `{
// 		"subject": {{ toJson .Subject }},
// 		"sans": [{
// 			"type": "permanentIdentifier",
// 			"value": {{ toJson .Subject.CommonName }}
// 		}]
// 	}`
// 	permanentIdentifierTemplateExtension, err := createSubjectAltNameExtension(nil, nil, nil, nil, []x509util.SubjectAlternativeName{
// 		{Type: PermanentIdentifierType, Value: "123456789"},
// 	}, false)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	csr, err := cr.GetCertificateRequest()
// 	require.NoError(t, err)

// 	sanExt, err := x509ext.MarshalSubjectAltName(&x509ext.SubjectAltName{
// 		PermanentIdentifiers: []x509ext.PermanentIdentifier{
// 			{
// 				IdentifierValue: "test-permanent-identifier",
// 			},
// 		},
// 	})
// 	require.NoError(t, err)
// 	csr.ExtraExtensions = append(csr.ExtraExtensions, sanExt)

// 	cert, err := ca.SignCSR(csr)
// 	require.NoError(t, err)

// 	ak := &AK{
// 		name:      "ak1",
// 		data:      []byte{1, 2, 3, 4},
// 		chain:     []*x509.Certificate{cert, ca.Intermediate},
// 		createdAt: time.Time{},
// 	}

// 	fmt.Println(fmt.Sprintf("%#+v", cert))

// 	tests := []struct {
// 		name                string
// 		ak                  *AK
// 		permanentIdentifier string
// 		want                bool
// 	}{
// 		{
// 			ak:                  ak,
// 			permanentIdentifier: "test-permanent-identifier",
// 			want:                true,
// 		},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			if got := tt.ak.HasValidPermanentIdentifier(tt.permanentIdentifier); got != tt.want {
// 				t.Errorf("AK.HasValidPermanentIdentifier() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }
