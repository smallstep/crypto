package tpm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
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

type mockClient struct {
	doFunc func(req *http.Request) (*http.Response, error)
}

// Do is the mock client's `Do` func
func (m *mockClient) Do(req *http.Request) (*http.Response, error) {
	if m.doFunc != nil {
		return m.doFunc(req)
	}
	return nil, errors.New("mocked doFunc not set")
}

func Test_downloader_downloadEKCertifiate(t *testing.T) {
	t.Parallel()
	client := &mockClient{
		doFunc: func(req *http.Request) (*http.Response, error) {
			switch {
			case req.URL.String() == "https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D":
				r := io.NopCloser(bytes.NewReader([]byte(intelEKMockResponse)))
				return &http.Response{
					StatusCode: 200,
					Body:       r,
				}, nil
			case req.URL.String() == "https://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121":
				b, err := base64.StdEncoding.DecodeString(amdEKRootMockResponse)
				require.NoError(t, err)
				r := io.NopCloser(bytes.NewReader(b))
				return &http.Response{
					StatusCode: 200,
					Body:       r,
				}, nil
			}
			return nil, errors.New("unexpected URL")
		},
	}
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
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d := &downloader{enabled: true, maxDownloads: 10, client: client}
			ekURL, err := url.Parse(tc.ekURL)
			require.NoError(t, err)

			got, err := d.downloadEKCertificate(tc.ctx, ekURL)
			if (err != nil) != tc.wantErr {
				t.Errorf("downloader.downloadEKCertifiate() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if assert.NoError(t, err) {
				assert.NotNil(t, got)
				assert.NotEmpty(t, got.Raw)
				if got.Subject.String() != tc.wantSubject {
					t.Errorf("downloader.downloadEKCertifiate() = %v, want %v", got.Subject.String(), tc.wantSubject)
				}
			}
		})
	}
}

const (
	// JSON response for https://ekop.intel.com/ekcertservice/WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D; also see https://github.com/tpm2-software/tpm2-tools/blob/master/test/integration/tests/getekcertificate.sh
	intelEKMockResponse = `{"pubhash":"WVEG2rRwkQ7m3RpXlUphgo6Y2HLxl18h6ZZkkOAdnBE%3D","certificate":"MIIEnDCCBEOgAwIBAgIEfT80-DAKBggqhkjOPQQDAjCBlTELMAkGA1UEBgwCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xLzAtBgNVBAsMJlRQTSBFSyBpbnRlcm1lZGlhdGUgZm9yIFNQVEhfRVBJRF9QUk9EMRYwFAYDVQQDDA13d3cuaW50ZWwuY29tMB4XDTE1MDUyMjAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMMg4vJEqGAarPPgHSbGZSSZNVYt4doZfp5_B2xGlhPPtlPpjsLDhvwdEz8sjGzDOLcy8LIIvYOKh3o-W7w-HUCE6DXHyJBqHAW00tMP2-vB262VD6axZb1LaoZGAxRhZMDE9Z1IkBHvH5KN7qbpAGHz03XlZGJzFR72IiUgmL4aSrAdwKEiJ8YJ_azrEVr0CNRpOm9JkZd0aVsMErwYof9xIKczey-18ZUdi7fwlNW1VMEclSOzByn-ZHh9ChO55jBIjatN_YZjSlJw7HL8xaRNxnmo8yk43YGX4p2ug59bTKD13ifJUiwjxU4cLOV4WVJRGL1EcLGBgO73iuQme80CAwEAAaOCAkgwggJEMA8GA1UdEwEB_wQFMAMBAQAwDgYDVR0PAQH_BAQDAgAgMBAGA1UdJQQJMAcGBWeBBQgBMCQGA1UdCQEBAAQaMBgwFgYFZ4EFAhAxDTALDAMyLjACAQACAWcwUAYDVR0RAQH_BEYwRKRCMEAxFjAUBgVngQUCAQwLaWQ6NDk0RTU0NDMxDjAMBgVngQUCAgwDU1BUMRYwFAYFZ4EFAgMMC2lkOjAwMDIwMDAwMB8GA1UdIwQYMBaAFF5zyJqj6QKycrnwdB99hzDj7HJKMFgGA1UdHwRRME8wTaBLoEmGR2h0dHA6Ly91cGdyYWRlcy5pbnRlbC5jb20vY29udGVudC9DUkwvZWtjZXJ0L1NQVEhFUElEUFJPRF9FS19EZXZpY2UuY3JsMHAGCCsGAQUFBwEBBGQwYjBgBggrBgEFBQcwAoZUaHR0cDovL3VwZ3JhZGVzLmludGVsLmNvbS9jb250ZW50L0NSTC9la2NlcnQvU1BUSEVQSURQUk9EX0VLX1BsYXRmb3JtX1B1YmxpY19LZXkuY2VyMIGpBgNVHSAEgaEwgZ4wgZsGCiqGSIb4TQEFAgEwgYwwUgYIKwYBBQUHAgEWRmh0dHA6Ly91cGdyYWRlcy5pbnRlbC5jb20vY29udGVudC9DUkwvZWtjZXJ0L0VLY2VydFBvbGljeVN0YXRlbWVudC5wZGYwNgYIKwYBBQUHAgIwKgwoVENQQSBUcnVzdGVkIFBsYXRmb3JtIE1vZHVsZSBFbmRvcnNlbWVudDAKBggqhkjOPQQDAgNHADBEAiBrQr0ckEoWsrx0971bppP6N8PTb4U6z_hIqpS6o150xAIgNxZNXq7bCqU1b4hGdiSBauowiOVFcaaiTm1p99H_k1Q%3D"}`

	// base64 encoded response for https://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121
	amdEKRootMockResponse = `MIIEiDCCA3CgAwIBAgIQJk05ojzrXVtJ1hAETuvRITANBgkqhkiG9w0BAQsFADB2MRQwEgYDVQQLEwtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxEjAQBgNVBAcTCVN1bm55dmFsZTELMAkGA1UECBMCQ0ExHzAdBgNVBAoTFkFkdmFuY2VkIE1pY3JvIERldmljZXMxDzANBgNVBAMTBkFNRFRQTTAeFw0xNDEwMjMxNDM0MzJaFw0zOTEwMjMxNDM0MzJaMHYxFDASBgNVBAsTC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzESMBAGA1UEBxMJU3Vubnl2YWxlMQswCQYDVQQIEwJDQTEfMB0GA1UEChMWQWR2YW5jZWQgTWljcm8gRGV2aWNlczEPMA0GA1UEAxMGQU1EVFBNMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAssnOAYu5nRflQk0bVtsTFcLSAMx9odZ4Ey3n6/MA6FD7DECIE70RGZgaRIID0eb+dyX3znMrp1TS+lD+GJSw7yDJrKeU4it8cMLqFrqGm4SEx/X5GBa11sTmL4i60pJ5nDo2T69OiJ+iqYzgBfYJLqHQaeSRN6bBYyn3w1H4JNzPDNvqKHvkPfYewHjUAFJAI1dShYO8REnNCB8eeolj375nymfAAZzgA8v7zmFX/1tVLCy7Mm6n7zndT452TB1mek9LC5LkwlnyABwaN2Q8LV4NWpIAzTgr55xbU5VvgcIpw+/qcbYHmqL6ZzCSeE1gRKQXlsybK+W4phCtQfMgHQIDAQABo4IBEDCCAQwwDgYDVR0PAQH/BAQDAgEGMCMGCSsGAQQBgjcVKwQWBBRXjFRfeWlRQhIhpKV4rNtfaC+JyDAdBgNVHQ4EFgQUV4xUX3lpUUISIaSleKzbX2gvicgwDwYDVR0TAQH/BAUwAwEB/zA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUHMAGGHGh0dHA6Ly9mdHBtLmFtZC5jb20vcGtpL29jc3AwLAYDVR0fBCUwIzAhoB+gHYYbaHR0cDovL2Z0cG0uYW1kLmNvbS9wa2kvY3JsMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIBFhxodHRwczovL2Z0cG0uYW1kLmNvbS9wa2kvY3BzMA0GCSqGSIb3DQEBCwUAA4IBAQCWB9yAoYYIt5HRY/OqJ5LUacP6rNmsMfPUDTcahXB3iQmY8HpUoGB23lhxbq+kz3vIiGAcUdKHlpB/epXyhABGTcJrNPMfx9akLqhI7WnMCPBbHDDDzKjjMB3Vm65PFbyuqbLujN/sN6kNtc4hL5r5Pr6Mze5H9WXBo2F2Oy+7+9jWMkxNrmUhoUUrF/6YsajTGPeq7r+i6q84W2nJdd+BoQQv4sk5GeuN2j2u4k1a8DkRPsVPc2I9QTtbzekchTK1GCXWki3DKGkZUEuaoaa60Kgw55Q5rt1eK7HKEG5npmR8aEod7BDLWy4CMTNAWR5iabCW/KX28JbJL6Phau9j`
)
