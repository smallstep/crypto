package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/smallstep/assert"
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

func Test_downloader_downloadEKCertifiate(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		ekURL       string
		wantSubject string
		wantErr     bool
	}{
		{
			name:        "intel",
			ctx:         context.Background(),
			ekURL:       "https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D",
			wantSubject: "", // no subject in EK certificate
			wantErr:     false,
		},
		{
			name:        "amd EK CA root",
			ctx:         context.Background(),
			ekURL:       "https://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121",            // assumes AMD EK certificate responses are all in the same format
			wantSubject: "CN=AMDTPM,OU=Engineering,O=Advanced Micro Devices,L=Sunnyvale,ST=CA,C=US", // AMDTPM EK CA root subject
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &downloader{enabled: true, maxDownloads: 10}
			ekURL, err := url.Parse(tt.ekURL)
			require.NoError(t, err)
			got, err := d.downloadEKCertifiate(tt.ctx, ekURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("downloader.downloadEKCertifiate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if assert.NoError(t, err) {
				assert.NotNil(t, got)
				if got.Subject.String() != tt.wantSubject {
					t.Errorf("downloader.downloadEKCertifiate() = %v, want %v", got.Subject.String(), tt.wantSubject)
				}
			}
		})
	}
}
