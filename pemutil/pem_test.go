package pemutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/x25519"
)

type keyType int

const (
	ecdsaPublicKey keyType = iota
	ecdsaPrivateKey
	ed25519PublicKey
	ed25519PrivateKey
	rsaPublicKey
	rsaPrivateKey
	x25519PublicKey
	x25519PrivateKey
)

const (
	testCRT = `-----BEGIN CERTIFICATE-----
MIICLjCCAdSgAwIBAgIQBvswFbAODY9xtJ/myiuEHzAKBggqhkjOPQQDAjAkMSIw
IAYDVQQDExlTbWFsbHN0ZXAgSW50ZXJtZWRpYXRlIENBMB4XDTE4MTEzMDE5NTkw
OVoXDTE4MTIwMTE5NTkwOVowHjEcMBoGA1UEAxMTaGVsbG8uc21hbGxzdGVwLmNv
bTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIqPQy8roJTMWpEt8NNA1CnRm3l1
wdjH4OrVaH3l2Gp/UW737Wbn4sqSAFahmajuwkfRG5KMh2/+xnCkGuR2fayjge0w
geowDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAdBgNVHQ4EFgQU5bqyXvZaEmtZ3OpZapq7pBIkVvgwHwYDVR0jBBgwFoAUu97P
aFQPfuyKOeew7Hg45WFIAVMwHgYDVR0RBBcwFYITaGVsbG8uc21hbGxzdGVwLmNv
bTBZBgwrBgEEAYKkZMYoQAEESTBHAgEBBBVtYXJpYW5vQHNtYWxsc3RlcC5jb20E
K2pPMzdkdERia3UtUW5hYnM1VlIwWXc2WUZGdjl3ZUExOGRwM2h0dmRFanMwCgYI
KoZIzj0EAwIDSAAwRQIhALKeC2q0HWyHoZobZFK9HQynLbPOOtAK437RaetlX5ty
AiBXQzvaLlDprQu+THj18aDYLnHA//5mdD3HPJV6KmgdDg==
-----END CERTIFICATE-----`
	testCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIHYMIGAAgEAMB4xHDAaBgNVBAMTE2hlbGxvLnNtYWxsc3RlcC5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASKj0MvK6CUzFqRLfDTQNQp0Zt5dcHYx+Dq1Wh9
5dhqf1Fu9+1m5+LKkgBWoZmo7sJH0RuSjIdv/sZwpBrkdn2soAAwCgYIKoZIzj0E
AwIDRwAwRAIgZgz9gdx9inOp6bSX4EkYiUCyLV9xGvabovu5C9UkRr8CIBGBbkp0
l4tesAKoXelsLygJjPuUGRLK+OtdjPBIN1Zo
-----END CERTIFICATE REQUEST-----`
	testCSRKeytool = `-----BEGIN NEW CERTIFICATE REQUEST-----
MIHYMIGAAgEAMB4xHDAaBgNVBAMTE2hlbGxvLnNtYWxsc3RlcC5jb20wWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASKj0MvK6CUzFqRLfDTQNQp0Zt5dcHYx+Dq1Wh9
5dhqf1Fu9+1m5+LKkgBWoZmo7sJH0RuSjIdv/sZwpBrkdn2soAAwCgYIKoZIzj0E
AwIDRwAwRAIgZgz9gdx9inOp6bSX4EkYiUCyLV9xGvabovu5C9UkRr8CIBGBbkp0
l4tesAKoXelsLygJjPuUGRLK+OtdjPBIN1Zo
-----END NEW CERTIFICATE REQUEST-----`
)

type testdata struct {
	typ       keyType
	encrypted bool
}

var files = map[string]testdata{
	"testdata/openssl.p256.pem":              {ecdsaPrivateKey, false},
	"testdata/openssl.p256.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssl.p256.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssl.p384.pem":              {ecdsaPrivateKey, false},
	"testdata/openssl.p384.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssl.p384.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssl.p521.pem":              {ecdsaPrivateKey, false},
	"testdata/openssl.p521.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssl.p521.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssl.rsa1024.pem":           {rsaPrivateKey, false},
	"testdata/openssl.rsa1024.pub.pem":       {rsaPublicKey, false},
	"testdata/openssl.rsa1024.enc.pem":       {rsaPrivateKey, true},
	"testdata/openssl.rsa2048.pem":           {rsaPrivateKey, false},
	"testdata/openssl.rsa2048.pub.pem":       {rsaPublicKey, false},
	"testdata/openssl.rsa2048.enc.pem":       {rsaPrivateKey, true},
	"testdata/openssh.ed25519.enc.pem":       {ed25519PrivateKey, true},
	"testdata/openssh.ed25519.pem":           {ed25519PrivateKey, false},
	"testdata/openssh.ed25519.pub.pem":       {ed25519PublicKey, false},
	"testdata/openssh.p256.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssh.p256.pem":              {ecdsaPrivateKey, false},
	"testdata/openssh.p256.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssh.p384.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssh.p384.pem":              {ecdsaPrivateKey, false},
	"testdata/openssh.p384.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssh.p521.enc.pem":          {ecdsaPrivateKey, true},
	"testdata/openssh.p521.pem":              {ecdsaPrivateKey, false},
	"testdata/openssh.p521.pub.pem":          {ecdsaPublicKey, false},
	"testdata/openssh.rsa1024.enc.pem":       {rsaPrivateKey, true},
	"testdata/openssh.rsa1024.pem":           {rsaPrivateKey, false},
	"testdata/openssh.rsa1024.pub.pem":       {rsaPublicKey, false},
	"testdata/openssh.rsa2048.enc.pem":       {rsaPrivateKey, true},
	"testdata/openssh.rsa2048.pem":           {rsaPrivateKey, false},
	"testdata/openssh.rsa2048.pub.pem":       {rsaPublicKey, false},
	"testdata/pkcs8/openssl.ed25519.pem":     {ed25519PrivateKey, false},
	"testdata/pkcs8/openssl.ed25519.pub.pem": {ed25519PublicKey, false},
	"testdata/pkcs8/openssl.ed25519.enc.pem": {ed25519PrivateKey, true},
	"testdata/pkcs8/openssl.p256.pem":        {ecdsaPrivateKey, false},
	"testdata/pkcs8/openssl.p256.pub.pem":    {ecdsaPublicKey, false},
	"testdata/pkcs8/openssl.p256.enc.pem":    {ecdsaPrivateKey, true},
	"testdata/pkcs8/openssl.p384.pem":        {ecdsaPrivateKey, false},
	"testdata/pkcs8/openssl.p384.pub.pem":    {ecdsaPublicKey, false},
	"testdata/pkcs8/openssl.p384.enc.pem":    {ecdsaPrivateKey, true},
	"testdata/pkcs8/openssl.p521.pem":        {ecdsaPrivateKey, false},
	"testdata/pkcs8/openssl.p521.pub.pem":    {ecdsaPublicKey, false},
	"testdata/pkcs8/openssl.p521.enc.pem":    {ecdsaPrivateKey, true},
	"testdata/pkcs8/openssl.rsa2048.pem":     {rsaPrivateKey, false},
	"testdata/pkcs8/openssl.rsa2048.pub.pem": {rsaPublicKey, false},
	"testdata/pkcs8/openssl.rsa2048.enc.pem": {rsaPrivateKey, true},
	"testdata/pkcs8/openssl.rsa4096.pem":     {rsaPrivateKey, false},
	"testdata/pkcs8/openssl.rsa4096.pub.pem": {rsaPublicKey, false},
	"testdata/cosign.pub.pem":                {ecdsaPublicKey, false},
	"testdata/cosign.enc.pem":                {ecdsaPrivateKey, true},
	"testdata/nebula.pub":                    {x25519PublicKey, false},
	"testdata/nebula.key":                    {x25519PrivateKey, false},
}

func readOrParseSSH(fn string) (interface{}, error) {
	if strings.HasPrefix(fn, "testdata/openssh") && strings.HasSuffix(fn, ".pub.pem") {
		b, err := os.ReadFile(fn)
		if err != nil {
			return nil, err
		}
		return ParseSSH(b)
	}
	return Read(fn)
}

func TestRead(t *testing.T) {
	var err error
	var key interface{}

	for fn, td := range files {
		t.Run(fn, func(t *testing.T) {
			if td.encrypted {
				key, err = Read(fn, WithPassword([]byte("mypassword")))
			} else {
				key, err = readOrParseSSH(fn)
			}

			assert.NotNil(t, key)
			assert.NoError(t, err)

			switch td.typ {
			case ecdsaPublicKey:
				assert.IsType(t, &ecdsa.PublicKey{}, key)
			case ecdsaPrivateKey:
				assert.IsType(t, &ecdsa.PrivateKey{}, key)
			case ed25519PublicKey:
				assert.IsType(t, ed25519.PublicKey{}, key)
			case ed25519PrivateKey:
				assert.IsType(t, ed25519.PrivateKey{}, key)
			case rsaPublicKey:
				assert.IsType(t, &rsa.PublicKey{}, key)
			case rsaPrivateKey:
				assert.IsType(t, &rsa.PrivateKey{}, key)
			case x25519PublicKey:
				assert.IsType(t, x25519.PublicKey{}, key)
			case x25519PrivateKey:
				assert.IsType(t, x25519.PrivateKey{}, key)
			default:
				t.Errorf("type %T not supported", key)
			}

			// Check encrypted against non-encrypted
			if td.encrypted {
				k, err := Read(strings.Replace(fn, ".enc", "", 1))
				assert.NoError(t, err)
				assert.Equal(t, k, key)
			}

			// Check against public
			switch td.typ {
			case ecdsaPrivateKey, ed25519PrivateKey, rsaPrivateKey:
				pub := strings.Replace(fn, ".enc", "", 1)
				pub = strings.Replace(pub, "pem", "pub.pem", 1)

				k, err := readOrParseSSH(pub)
				assert.NoError(t, err)

				if pk, ok := key.(crypto.Signer); ok {
					assert.Equal(t, k, pk.Public())

					var signature, digest []byte
					message := []byte("message")
					if _, ok := pk.(ed25519.PrivateKey); ok {
						signature, err = pk.Sign(rand.Reader, message, crypto.Hash(0))
					} else {
						sum := sha256.Sum256(message)
						digest = sum[:]
						signature, err = pk.Sign(rand.Reader, digest, crypto.SHA256)
					}
					assert.NoError(t, err)
					switch k := k.(type) {
					case *ecdsa.PublicKey:
						// See ecdsa.Sign https://golang.org/pkg/crypto/ecdsa/#Sign
						ecdsaSignature := struct {
							R, S *big.Int
						}{}
						_, err := asn1.Unmarshal(signature, &ecdsaSignature)
						assert.NoError(t, err)
						verified := ecdsa.Verify(k, digest, ecdsaSignature.R, ecdsaSignature.S)
						assert.True(t, verified)
					case ed25519.PublicKey:
						verified := ed25519.Verify(k, []byte("message"), signature)
						assert.True(t, verified)
					case *rsa.PublicKey:
						err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, signature)
						assert.NoError(t, err)
					}

				} else {
					t.Errorf("key for %s does not satisfies the crypto.Signer interface", fn)
				}
			}
		})
	}
}

func TestParseCertificate(t *testing.T) {
	tests := []struct {
		fn  string
		err error
	}{
		{"testdata/ca.crt", nil},
		{"testdata/bundle.crt", nil},
		{"testdata/badca.crt", errors.New("error parsing certificate")},
		{"testdata/badpem.crt", errors.New("error decoding pem block")},
		{"testdata/badder.crt", errors.New("error decoding pem block")},
		{"testdata/openssl.p256.pem", errors.New("error parsing certificate: no certificate found")},
	}

	for _, tc := range tests {
		t.Run(tc.fn, func(t *testing.T) {
			b, err := os.ReadFile(tc.fn)
			if err != nil {
				t.Fatal(err)
			}
			crt, err := ParseCertificate(b)
			if tc.err != nil {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.NoError(t, err)
				assert.IsType(t, &x509.Certificate{}, crt)
			}
		})
	}
}

func TestReadCertificate(t *testing.T) {
	tests := []struct {
		fn   string
		opts []Options
		err  error
	}{
		{"testdata/ca.crt", nil, nil},
		{"testdata/nonPEMHeaderCa.crt", nil, nil},
		{"testdata/extrajunkbundle.crt", []Options{WithFirstBlock()}, nil},
		{"testdata/ca.der", nil, nil},
		{"testdata/bundle.crt", []Options{WithFirstBlock()}, nil},
		{"testdata/bundle.crt", nil, errors.New("error decoding testdata/bundle.crt: contains more than one PEM encoded block")},
		{"testdata/notexists.crt", nil, errors.New(`error reading "testdata/notexists.crt": no such file or directory`)},
		{"testdata/badca.crt", nil, errors.New("error parsing testdata/badca.crt")},
		{"testdata/badpem.crt", nil, errors.New("error parsing testdata/badpem.crt: does not contain a valid PEM encoded certificate")},
		{"testdata/badder.crt", nil, errors.New("error parsing testdata/badder.crt")},
		{"testdata/openssl.p256.pem", nil, errors.New("error parsing testdata/openssl.p256.pem: does not contain a valid PEM encoded certificate")},
	}

	for _, tc := range tests {
		t.Run(tc.fn, func(t *testing.T) {
			crt, err := ReadCertificate(tc.fn, tc.opts...)
			if tc.err != nil {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.NoError(t, err)
				assert.IsType(t, &x509.Certificate{}, crt)
			}
		})
	}
}

func TestReadCertificateBundle(t *testing.T) {
	tests := []struct {
		fn  string
		len int
		err error
	}{
		{"testdata/ca.crt", 1, nil},
		{"testdata/nonPEMHeaderCa.crt", 1, nil},
		{"testdata/ca.der", 1, nil},
		{"testdata/bundle.crt", 2, nil},
		{"testdata/extrajunkbundle.crt", 2, nil},
		{"testdata/notexists.crt", 0, errors.New(`error reading "testdata/notexists.crt": no such file or directory`)},
		{"testdata/badca.crt", 0, errors.New("error parsing testdata/badca.crt")},
		{"testdata/badpem.crt", 0, errors.New("error parsing testdata/badpem.crt: does not contain a valid PEM encoded certificate")},
		{"testdata/badder.crt", 0, errors.New("error parsing testdata/badder.crt")},
		{"testdata/openssl.p256.pem", 0, errors.New("error parsing testdata/openssl.p256.pem: does not contain a valid PEM encoded certificate")},
	}

	for _, tc := range tests {
		t.Run(tc.fn, func(t *testing.T) {
			certs, err := ReadCertificateBundle(tc.fn)
			if tc.err != nil {
				if assert.Error(t, err, tc.fn, "- expected error but got nil") {
					assert.Contains(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, certs, tc.len, tc.fn)
				for i := range certs {
					assert.IsType(t, &x509.Certificate{}, certs[i])
				}
			}
		})
	}
}

func TestParseCertificateBundle(t *testing.T) {
	tests := []struct {
		name string
		fn   string
		len  int
		err  error
	}{
		{"ok cert", "testdata/ca.crt", 1, nil},
		{"ok non PEM header", "testdata/nonPEMHeaderCa.crt", 1, nil},
		{"ok der", "testdata/ca.der", 1, nil},
		{"ok bundle", "testdata/bundle.crt", 2, nil},
		{"ok extra junk in bundle", "testdata/extrajunkbundle.crt", 2, nil},
		{"fail bad cert w/ file", "testdata/badca.crt", 0, errors.New("error decoding PEM data: x509: trailing data")},
		{"fail no PEM", "testdata/badpem.crt", 0, errors.New("does not contain a valid PEM encoded certificate")},
		{"fail no PEM", "testdata/badpem.crt", 0, errors.New("does not contain a valid PEM encoded certificate")},
		{"fail bad der", "testdata/badder.crt", 0, errors.New("error parsing certificate as DER format: x509: malformed certificate")},
		{"fail no valid PEM", "testdata/openssl.p256.pem", 0, errors.New("does not contain a valid PEM encoded certificate")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile(tc.fn)
			if err != nil {
				t.Fatal(err)
			}
			certs, err := ParseCertificateBundle(b)
			if tc.err != nil {
				if assert.Error(t, err, tc.fn, "- expected error but got nil") {
					assert.Contains(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.NoError(t, err)
				assert.Len(t, certs, tc.len, tc.fn)
				for i := range certs {
					assert.IsType(t, &x509.Certificate{}, certs[i])
				}
			}
		})
	}
}

func TestParse(t *testing.T) {
	type ParseTest struct {
		in      []byte
		opts    []Options
		cmpType interface{}
		err     error
	}
	tests := map[string]func(t *testing.T) *ParseTest{
		"success-ecdsa-public-key": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/openssl.p256.pub.pem")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &ecdsa.PublicKey{},
			}
		},
		"success-rsa-public-key": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/openssl.rsa1024.pub.pem")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &rsa.PublicKey{},
			}
		},
		"success-rsa-private-key": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/openssl.rsa1024.pem")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &rsa.PrivateKey{},
			}
		},
		"success-ecdsa-private-key": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/openssl.p256.pem")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &ecdsa.PrivateKey{},
			}
		},
		"success-ed25519-private-key": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/pkcs8/openssl.ed25519.pem")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: ed25519.PrivateKey{},
			}
		},
		"success-ed25519-enc-private-key": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/pkcs8/openssl.ed25519.enc.pem")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    []Options{WithPassword([]byte("mypassword"))},
				cmpType: ed25519.PrivateKey{},
			}
		},
		"success-x509-crt": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/ca.crt")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &x509.Certificate{},
			}
		},
		"success-x509-crt-trim-spaces": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/ca.crt")
			require.NoError(t, err)
			b = append(b, []byte(" \n \n ")...)
			return &ParseTest{
				in:      b,
				opts:    nil,
				cmpType: &x509.Certificate{},
			}
		},
		"fail-options": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/ca.crt")
			require.NoError(t, err)
			err = errors.New("an error")
			return &ParseTest{
				in:      b,
				opts:    []Options{func(ctx *context) error { return err }},
				cmpType: err,
				err:     err,
			}
		},
		"fail-password": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/openssl.p256.enc.pem")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    []Options{WithPassword([]byte("badpassword"))},
				cmpType: ecdsa.PrivateKey{},
				err:     errors.New("error decrypting PEM"),
			}
		},
		"fail-pkcs8-password": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/pkcs8/openssl.ed25519.enc.pem")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    []Options{WithPassword([]byte("badpassword"))},
				cmpType: ed25519.PrivateKey{},
				err:     errors.New("error decrypting PEM: x509: decryption password incorrect"),
			}
		},
		"fail-type": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/openssl.p256.pub.pem")
			require.NoError(t, err)
			b = bytes.ReplaceAll(b, []byte("PUBLIC KEY"), []byte("EC PUBLIC KEY"))
			return &ParseTest{
				in:      b,
				opts:    []Options{},
				cmpType: nil,
				err:     errors.New("error decoding PEM: contains an unexpected header 'EC PUBLIC KEY'"),
			}
		},
		"fail-nebula-pub-size": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/badnebula.pub")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    []Options{},
				cmpType: nil,
				err:     errors.New("error parsing PEM: key is not 32 bytes"),
			}
		},
		"fail-nebula-key-size": func(t *testing.T) *ParseTest {
			b, err := os.ReadFile("testdata/badnebula.key")
			require.NoError(t, err)
			return &ParseTest{
				in:      b,
				opts:    []Options{},
				cmpType: nil,
				err:     errors.New("error parsing PEM: key is not 32 bytes"),
			}
		},
	}
	for name, genTestCase := range tests {
		t.Run(name, func(t *testing.T) {
			tc := genTestCase(t)

			i, err := Parse(tc.in, tc.opts...)
			if err != nil {
				if assert.NotNil(t, tc.err) {
					assert.Contains(t, err.Error(), tc.err.Error())
				}
			} else {
				if assert.Nil(t, tc.err) {
					assert.IsType(t, i, tc.cmpType)
				}
			}
		})
	}
}

//nolint:staticcheck // required for legacy compatibility
func TestSerialize(t *testing.T) {
	tests := map[string]struct {
		in    func() (interface{}, error)
		pass  string
		pkcs8 bool
		file  string
		err   error
	}{
		"unrecognized key type": {
			in: func() (interface{}, error) {
				return "shake and bake", nil
			},
			err: errors.New("cannot serialize type 'string', value 'shake and bake'"),
		},
		"RSA Private Key success": {
			in: func() (interface{}, error) {
				return keyutil.GenerateKey("RSA", "", 2048)
			},
		},
		"RSA Public Key success": {
			in: func() (interface{}, error) {
				pub, _, err := keyutil.GenerateKeyPair("RSA", "", 2048)
				return pub, err
			},
		},
		"EC Private Key success": {
			in: func() (interface{}, error) {
				return keyutil.GenerateKey("EC", "P-256", 0)
			},
		},
		"EC Private Key success - encrypt input data": {
			in: func() (interface{}, error) {
				return keyutil.GenerateKey("EC", "P-256", 0)
			},
			pass: "pass",
		},
		"EC Private Key success - encrypt pkcs8 data": {
			in: func() (interface{}, error) {
				return keyutil.GenerateKey("EC", "P-256", 0)
			},
			pass:  "pass",
			pkcs8: true,
		},
		"EC Public Key success": {
			in: func() (interface{}, error) {
				pub, _, err := keyutil.GenerateKeyPair("EC", "P-256", 0)
				return pub, err
			},
		},
		"OKP Private Key success": {
			in: func() (interface{}, error) {
				return keyutil.GenerateKey("OKP", "Ed25519", 0)
			},
		},
		"OKP Public Key success": {
			in: func() (interface{}, error) {
				pub, _, err := keyutil.GenerateKeyPair("OKP", "Ed25519", 0)
				return pub, err
			},
		},
		"X.509 Certificate success": {
			in: func() (interface{}, error) {
				return ReadCertificate("testdata/ca.crt")
			},
		},
		"X.509 Certificate request success": {
			in: func() (interface{}, error) {
				return &x509.CertificateRequest{}, nil
			},
		},
		"propagate open key out file error": {
			in: func() (interface{}, error) {
				return keyutil.GenerateKey("EC", "P-256", 0)
			},
			file: "./fakeDir/test.key",
			err:  errors.New("error writing ./fakeDir/test.key: no such file or directory"),
		},
		"ToFile Success (EC Private Key unencrypted)": {
			in: func() (interface{}, error) {
				return keyutil.GenerateKey("EC", "P-256", 0)
			},
			file: "./test.key",
		},
		"ToFile Success (EC Private Key encrypted)": {
			in: func() (interface{}, error) {
				return keyutil.GenerateKey("EC", "P-256", 0)
			},
			pass: "pass",
			file: "./test.key",
		},
	}

	for name, test := range tests {
		if _, err := os.Stat("./test.key"); err == nil {
			require.NoError(t, os.Remove("./test.key"))
		}
		t.Logf("Running test case: %s", name)

		in, err := test.in()
		require.NoError(t, err)

		var p *pem.Block
		switch {
		case test.pass == "" && test.file == "":
			p, err = Serialize(in)
		case test.pass != "" && test.file != "":
			p, err = Serialize(in, WithPassword([]byte(test.pass)), ToFile(test.file, 0o600))
		case test.pass != "" && test.pkcs8:
			p, err = Serialize(in, WithPKCS8(true), WithPasswordPrompt("Please enter the password to encrypt the key", func(prompt string) ([]byte, error) {
				return []byte(test.pass), nil
			}))
		case test.pass != "":
			p, err = Serialize(in, WithPassword([]byte(test.pass)))
		default:
			p, err = Serialize(in, ToFile(test.file, 0o600))
		}

		if err != nil {
			if assert.NotNil(t, test.err) {
				assert.Contains(t, err.Error(), test.err.Error())
			}
		} else {
			if assert.Nil(t, test.err) {
				switch k := in.(type) {
				case *x509.Certificate, *x509.CertificateRequest:
				case *rsa.PrivateKey:
					if test.pass == "" {
						assert.False(t, x509.IsEncryptedPEMBlock(p))
						assert.Equal(t, p.Type, "RSA PRIVATE KEY")
						assert.Equal(t, p.Bytes, x509.MarshalPKCS1PrivateKey(k))
					} else {
						assert.True(t, x509.IsEncryptedPEMBlock(p))
						assert.Equal(t, p.Type, "RSA PRIVATE KEY")
						assert.Equal(t, p.Headers["Proc-Type"], "4,ENCRYPTED")

						var der []byte
						der, err = x509.DecryptPEMBlock(p, []byte(test.pass))
						require.NoError(t, err)
						assert.Equal(t, der, x509.MarshalPKCS1PrivateKey(k))
					}
				case *rsa.PublicKey, *ecdsa.PublicKey:
					assert.False(t, x509.IsEncryptedPEMBlock(p))
					assert.Equal(t, p.Type, "PUBLIC KEY")

					var b []byte
					b, err = x509.MarshalPKIXPublicKey(k)
					require.NoError(t, err)
					assert.Equal(t, p.Bytes, b)
				case *ecdsa.PrivateKey:
					var actualBytes []byte
					switch {
					case test.pass == "":
						assert.Equal(t, p.Type, "EC PRIVATE KEY")
						assert.False(t, x509.IsEncryptedPEMBlock(p))
						actualBytes = p.Bytes
					case test.pkcs8:
						assert.Equal(t, p.Type, "ENCRYPTED PRIVATE KEY")
						actualBytes, err = DecryptPKCS8PrivateKey(p.Bytes, []byte(test.pass))
						require.NoError(t, err)
					default:
						assert.Equal(t, p.Type, "EC PRIVATE KEY")
						assert.True(t, x509.IsEncryptedPEMBlock(p))
						assert.Equal(t, p.Headers["Proc-Type"], "4,ENCRYPTED")
						actualBytes, err = x509.DecryptPEMBlock(p, []byte(test.pass))
						require.NoError(t, err)
					}
					var expectedBytes []byte
					if test.pkcs8 {
						expectedBytes, err = x509.MarshalPKCS8PrivateKey(k)
					} else {
						expectedBytes, err = x509.MarshalECPrivateKey(k)
					}
					require.NoError(t, err)
					assert.Equal(t, actualBytes, expectedBytes)

					if test.file != "" {
						// Check key permissions
						var fileInfo os.FileInfo
						fileInfo, err = os.Stat(test.file)
						require.NoError(t, err)
						assert.Equal(t, fileInfo.Mode(), os.FileMode(0o600))
						// Verify that key written to file is correct
						var keyFileBytes []byte
						keyFileBytes, err = os.ReadFile(test.file)
						require.NoError(t, err)
						pemKey, _ := pem.Decode(keyFileBytes)
						assert.Equal(t, pemKey.Type, "EC PRIVATE KEY")
						if x509.IsEncryptedPEMBlock(pemKey) {
							assert.Equal(t, pemKey.Headers["Proc-Type"], "4,ENCRYPTED")
							actualBytes, err = x509.DecryptPEMBlock(pemKey, []byte(test.pass))
							require.NoError(t, err)
						} else {
							actualBytes = pemKey.Bytes
						}
						assert.Equal(t, actualBytes, expectedBytes)
					}
				case ed25519.PrivateKey:
					assert.Equal(t, p.Type, "PRIVATE KEY")
					var actualBytes []byte
					if test.pass == "" {
						assert.False(t, x509.IsEncryptedPEMBlock(p))
						actualBytes = p.Bytes
					} else {
						assert.True(t, x509.IsEncryptedPEMBlock(p))
						assert.Equal(t, p.Headers["Proc-Type"], "4,ENCRYPTED")

						actualBytes, err = x509.DecryptPEMBlock(p, []byte(test.pass))
						require.NoError(t, err)
					}

					var priv pkcs8
					_, err = asn1.Unmarshal(actualBytes, &priv)
					require.NoError(t, err)
					assert.Equal(t, priv.Version, 0)
					assert.Equal(t, priv.Algo, pkix.AlgorithmIdentifier{
						Algorithm:  asn1.ObjectIdentifier{1, 3, 101, 112},
						Parameters: asn1.RawValue{},
					})
					assert.Equal(t, priv.PrivateKey[:2], []byte{4, 32})
					assert.Equal(t, priv.PrivateKey[2:ed25519.SeedSize+2], k.Seed())
				case ed25519.PublicKey:
					assert.Equal(t, p.Type, "PUBLIC KEY")
					assert.False(t, x509.IsEncryptedPEMBlock(p))

					var pub publicKeyInfo
					_, err = asn1.Unmarshal(p.Bytes, &pub)
					require.NoError(t, err)
					assert.Equal(t, pub.Algo, pkix.AlgorithmIdentifier{
						Algorithm:  asn1.ObjectIdentifier{1, 3, 101, 112},
						Parameters: asn1.RawValue{},
					})
					assert.Equal(t, pub.PublicKey, asn1.BitString{
						Bytes:     k,
						BitLength: ed25519.PublicKeySize * 8,
					})
				default:
					t.Errorf("Unrecognized key - type: %T, value: %v", k, k)
				}
			}
		}
		if _, err := os.Stat("./test.key"); err == nil {
			require.NoError(t, os.Remove("./test.key"))
		}
	}
}

func TestParseDER(t *testing.T) {
	k1, err := Read("testdata/openssl.rsa2048.pem")
	require.NoError(t, err)
	k2, err := Read("testdata/openssl.p256.pem")
	require.NoError(t, err)
	k3, err := Read("testdata/pkcs8/openssl.ed25519.pem")
	require.NoError(t, err)
	rsaKey := k1.(*rsa.PrivateKey)
	ecdsaKey := k2.(*ecdsa.PrivateKey)
	edKey := k3.(ed25519.PrivateKey)
	// Ed25519 der files
	edPubDer, err := os.ReadFile("testdata/pkcs8/openssl.ed25519.pub.der")
	require.NoError(t, err)
	edPrivDer, err := os.ReadFile("testdata/pkcs8/openssl.ed25519.der")
	require.NoError(t, err)

	toDER := func(k interface{}) []byte {
		switch k := k.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			b, err := x509.MarshalPKIXPublicKey(k)
			require.NoError(t, err)
			return b
		case *rsa.PrivateKey:
			return x509.MarshalPKCS1PrivateKey(k)
		case *ecdsa.PrivateKey:
			b, err := x509.MarshalECPrivateKey(k)
			require.NoError(t, err)
			return b
		default:
			t.Fatalf("unsupported key type %T", k)
			return nil
		}
	}

	type args struct {
		b []byte
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{"rsa public key", args{toDER(rsaKey.Public())}, rsaKey.Public(), false},
		{"rsa private key", args{toDER(rsaKey)}, rsaKey, false},
		{"rsa pkcs#1 public key", args{x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)}, rsaKey.Public(), false},
		{"ecdsa public key", args{toDER(ecdsaKey.Public())}, ecdsaKey.Public(), false},
		{"ecdsa private key", args{toDER(ecdsaKey)}, ecdsaKey, false},
		{"ed25519 public key", args{edPubDer}, edKey.Public(), false},
		{"ed25519 private key", args{edPrivDer}, edKey, false},
		{"fail", args{[]byte("fooo")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDER(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDER() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseDER() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseKey(t *testing.T) {
	var key interface{}
	for fn, td := range files {
		// skip ssh public keys
		if strings.HasPrefix(fn, "testdata/openssh") && strings.HasSuffix(fn, ".pub.pem") {
			continue
		}
		t.Run(fn, func(t *testing.T) {
			data, err := os.ReadFile(fn)
			require.NoError(t, err)
			if td.encrypted {
				key, err = ParseKey(data, WithPassword([]byte("mypassword")))
			} else {
				key, err = ParseKey(data)
			}
			assert.NotNil(t, key)
			assert.NoError(t, err)

			switch td.typ {
			case ecdsaPublicKey:
				assert.IsType(t, &ecdsa.PublicKey{}, key)
			case ecdsaPrivateKey:
				assert.IsType(t, &ecdsa.PrivateKey{}, key)
			case ed25519PublicKey:
				assert.IsType(t, ed25519.PublicKey{}, key)
			case ed25519PrivateKey:
				assert.IsType(t, ed25519.PrivateKey{}, key)
			case rsaPublicKey:
				assert.IsType(t, &rsa.PublicKey{}, key)
			case rsaPrivateKey:
				assert.IsType(t, &rsa.PrivateKey{}, key)
			case x25519PublicKey:
				assert.IsType(t, x25519.PublicKey{}, key)
			case x25519PrivateKey:
				assert.IsType(t, x25519.PrivateKey{}, key)
			default:
				t.Errorf("type %T not supported", key)
			}
		})
	}
}

func TestParseKey_x509(t *testing.T) {
	b, _ := pem.Decode([]byte(testCRT))
	cert, err := x509.ParseCertificate(b.Bytes)
	require.NoError(t, err)
	key, err := ParseKey([]byte(testCRT))
	require.NoError(t, err)
	assert.Equal(t, cert.PublicKey, key)

	b, _ = pem.Decode([]byte(testCSR))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	require.NoError(t, err)
	key, err = ParseKey([]byte(testCSR))
	require.NoError(t, err)
	assert.Equal(t, csr.PublicKey, key)

	b, _ = pem.Decode([]byte(testCSRKeytool))
	csr, err = x509.ParseCertificateRequest(b.Bytes)
	require.NoError(t, err)
	key, err = ParseKey([]byte(testCSRKeytool))
	require.NoError(t, err)
	assert.Equal(t, csr.PublicKey, key)
}

func TestParseSSH(t *testing.T) {
	var key interface{}
	for fn, td := range files {
		if !strings.HasPrefix(fn, "testdata/openssh") || !strings.HasSuffix(fn, ".pub.pem") {
			continue
		}
		t.Run(fn, func(t *testing.T) {
			data, err := os.ReadFile(fn)
			require.NoError(t, err)
			key, err = ParseSSH(data)
			require.NoError(t, err)
			assert.NotNil(t, key)

			switch td.typ {
			case ecdsaPublicKey:
				assert.IsType(t, &ecdsa.PublicKey{}, key)
			case ed25519PublicKey:
				assert.IsType(t, ed25519.PublicKey{}, key)
			case rsaPublicKey:
				assert.IsType(t, &rsa.PublicKey{}, key)
			default:
				t.Errorf("type %T not supported", key)
			}
		})
	}
}

func TestOpenSSH(t *testing.T) {
	t.Parallel()
	for fn, td := range files {
		if strings.HasSuffix(fn, ".pub.pem") {
			continue
		}
		// skip x25519 keys
		if td.typ == x25519PublicKey || td.typ == x25519PrivateKey {
			continue
		}

		t.Run(fn, func(t *testing.T) {
			t.Parallel()
			opts := []Options{
				WithOpenSSH(true),
				WithComment("test@smallstep.com"),
			}
			if td.encrypted {
				opts = append(opts, WithPassword([]byte("mypassword")))
			}

			key, err := Read(fn, opts...)
			require.NoError(t, err)

			// using their own methods
			block, err := SerializeOpenSSHPrivateKey(key, opts...)
			require.NoError(t, err)

			key2, err := ParseOpenSSHPrivateKey(pem.EncodeToMemory(block), opts...)
			require.NoError(t, err)

			assert.Equal(t, key, key2)

			// using main methods
			block2, err := Serialize(key2, opts...)
			require.NoError(t, err)
			// salt must be different
			assert.NotEqual(t, block, block2)

			key3, err := Parse(pem.EncodeToMemory(block2), opts...)
			require.NoError(t, err)
			assert.Equal(t, key2, key3)
		})
	}
}

func TestRead_options(t *testing.T) {
	mustKey := func(filename string) interface{} {
		b, err := os.ReadFile(filename)
		require.NoError(t, err)
		key, err := ssh.ParseRawPrivateKey(b)
		require.NoError(t, err)
		return key
	}

	p256Key := mustKey("testdata/openssl.p256.pem")
	type args struct {
		filename string
		opts     []Options
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{"withPassword", args{"testdata/openssl.p256.enc.pem", []Options{WithPassword([]byte("mypassword"))}}, p256Key, false},
		{"withPasswordFile", args{"testdata/openssl.p256.enc.pem", []Options{WithPasswordFile("testdata/password.txt")}}, p256Key, false},
		{"withPasswordPrompt", args{"testdata/openssl.p256.enc.pem", []Options{WithPasswordPrompt("Enter the password", func(s string) ([]byte, error) {
			return []byte("mypassword"), nil
		})}}, p256Key, false},
		{"missing", args{"testdata/missing.txt", nil}, nil, true},
		{"missingPassword", args{"testdata/openssl.p256.enc.pem", nil}, nil, true},
		{"withPasswordError", args{"testdata/openssl.p256.enc.pem", []Options{WithPassword([]byte("badpassword"))}}, nil, true},
		{"withPasswordFileError", args{"testdata/openssl.p256.enc.pem", []Options{WithPasswordFile("testdata/missing.txt")}}, nil, true},
		{"withPasswordPromptError", args{"testdata/openssl.p256.enc.pem", []Options{WithPasswordPrompt("Enter the password", func(s string) ([]byte, error) {
			return nil, errors.New("an error")
		})}}, nil, true},
		{"withPasswordFile", args{"testdata/openssl.p256.enc.pem", []Options{WithPasswordFile("testdata/password.txt")}}, p256Key, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Read(tt.args.filename, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Read() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWithMinLengthPasswordFile(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		file    string
		want    []byte
		wantErr bool
	}{
		{
			name:    "negative",
			length:  -5,
			file:    "testdata/password.txt",
			wantErr: false,
			want:    []byte("mypassword"),
		},
		{
			name:    "zero",
			length:  0,
			file:    "testdata/password.txt",
			wantErr: false,
			want:    []byte("mypassword"),
		},
		{
			name:    "greater-than-min-length",
			length:  9,
			file:    "testdata/password.txt",
			wantErr: false,
			want:    []byte("mypassword"),
		},
		{
			name:    "equal-min-length",
			length:  10,
			file:    "testdata/password.txt",
			wantErr: false,
			want:    []byte("mypassword"),
		},
		{
			name:    "less-than-min-length",
			length:  11,
			file:    "testdata/password.txt",
			wantErr: true,
		},
		{
			name:    "ignore-pre-post-whitespace-characters",
			length:  7,
			file:    "testdata/password2.txt",
			wantErr: true,
		},
		{
			name:    "ignore-pre-post-whitespace-characters-ok",
			length:  6,
			file:    "testdata/password2.txt",
			wantErr: false,
			want:    []byte("  pass"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newContext(tt.name)
			gotErr := WithMinLengthPasswordFile(tt.file, tt.length)(ctx) != nil
			if gotErr != tt.wantErr {
				t.Errorf("WithMinLengthPasswordFile(%v, %v) = %v, want %v", tt.file, tt.length, gotErr, tt.wantErr)
				return
			}
			if gotErr {
				return
			}
			if !bytes.Equal(ctx.password, tt.want) {
				t.Errorf("Expected %v, but got %v", tt.want, ctx.password)
			}
		})
	}
}

func TestRead_promptPassword(t *testing.T) {
	mustKey := func(filename string) interface{} {
		b, err := os.ReadFile(filename)
		require.NoError(t, err)
		key, err := ssh.ParseRawPrivateKey(b)
		require.NoError(t, err)
		return key
	}

	p256Key := mustKey("testdata/openssl.p256.pem")
	type args struct {
		filename         string
		passwordPrompter PasswordPrompter
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{"PromptPassword", args{"testdata/openssl.p256.enc.pem", func(s string) ([]byte, error) {
			return []byte("mypassword"), nil
		}}, p256Key, false},
		{"PromptPasswordBadPassword", args{"testdata/openssl.p256.enc.pem", func(s string) ([]byte, error) {
			return []byte("badPassword"), nil
		}}, nil, true},
		{"PromptPasswordError", args{"testdata/openssl.p256.enc.pem", func(s string) ([]byte, error) {
			return nil, errors.New("an error")
		}}, nil, true},
		{"PromptPasswordNil", args{"testdata/openssl.p256.enc.pem", nil}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			PromptPassword = tt.args.passwordPrompter
			got, err := Read(tt.args.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Read() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCertificateRequest(t *testing.T) {
	expected := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "hello.smallstep.com",
			Names:      []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "hello.smallstep.com"}},
		},
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X: new(big.Int).SetBytes([]byte{
				0x8a, 0x8f, 0x43, 0x2f, 0x2b, 0xa0, 0x94, 0xcc,
				0x5a, 0x91, 0x2d, 0xf0, 0xd3, 0x40, 0xd4, 0x29,
				0xd1, 0x9b, 0x79, 0x75, 0xc1, 0xd8, 0xc7, 0xe0,
				0xea, 0xd5, 0x68, 0x7d, 0xe5, 0xd8, 0x6a, 0x7f,
			}),
			Y: new(big.Int).SetBytes([]byte{
				0x51, 0x6e, 0xf7, 0xed, 0x66, 0xe7, 0xe2, 0xca,
				0x92, 0x00, 0x56, 0xa1, 0x99, 0xa8, 0xee, 0xc2,
				0x47, 0xd1, 0x1b, 0x92, 0x8c, 0x87, 0x6f, 0xfe,
				0xc6, 0x70, 0xa4, 0x1a, 0xe4, 0x76, 0x7d, 0xac,
			}),
		},
		PublicKeyAlgorithm: x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Signature: []byte{
			0x30, 0x44, 0x02, 0x20, 0x66, 0x0c, 0xfd, 0x81,
			0xdc, 0x7d, 0x8a, 0x73, 0xa9, 0xe9, 0xb4, 0x97,
			0xe0, 0x49, 0x18, 0x89, 0x40, 0xb2, 0x2d, 0x5f,
			0x71, 0x1a, 0xf6, 0x9b, 0xa2, 0xfb, 0xb9, 0x0b,
			0xd5, 0x24, 0x46, 0xbf, 0x02, 0x20, 0x11, 0x81,
			0x6e, 0x4a, 0x74, 0x97, 0x8b, 0x5e, 0xb0, 0x02,
			0xa8, 0x5d, 0xe9, 0x6c, 0x2f, 0x28, 0x09, 0x8c,
			0xfb, 0x94, 0x19, 0x12, 0xca, 0xf8, 0xeb, 0x5d,
			0x8c, 0xf0, 0x48, 0x37, 0x56, 0x68,
		},
	}
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.CertificateRequest
		wantErr bool
	}{
		{"ok", args{"testdata/test.csr"}, expected, false},
		{"ok der", args{"testdata/test.der"}, expected, false},
		{"ok keytool", args{"testdata/keytool.csr"}, expected, false},
		{"fail bad csr", args{"testdata/bad.csr"}, nil, true},
		{"fail certificate", args{"testdata/ca.crt"}, nil, true},
		{"fail certificate der", args{"testdata/ca.der"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile(tt.args.filename)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseCertificateRequest(b)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Cleanup raw data
			if got != nil {
				got.Raw = nil
				got.RawSubject = nil
				got.RawSubjectPublicKeyInfo = nil
				got.RawTBSCertificateRequest = nil
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCertificateRequest() = \n%#v, want \n%#v", got, tt.want)
			}
		})
	}
}

func TestReadCertificateRequest(t *testing.T) {
	expected := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "hello.smallstep.com",
			Names:      []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "hello.smallstep.com"}},
		},
		PublicKey: &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X: new(big.Int).SetBytes([]byte{
				0x8a, 0x8f, 0x43, 0x2f, 0x2b, 0xa0, 0x94, 0xcc,
				0x5a, 0x91, 0x2d, 0xf0, 0xd3, 0x40, 0xd4, 0x29,
				0xd1, 0x9b, 0x79, 0x75, 0xc1, 0xd8, 0xc7, 0xe0,
				0xea, 0xd5, 0x68, 0x7d, 0xe5, 0xd8, 0x6a, 0x7f,
			}),
			Y: new(big.Int).SetBytes([]byte{
				0x51, 0x6e, 0xf7, 0xed, 0x66, 0xe7, 0xe2, 0xca,
				0x92, 0x00, 0x56, 0xa1, 0x99, 0xa8, 0xee, 0xc2,
				0x47, 0xd1, 0x1b, 0x92, 0x8c, 0x87, 0x6f, 0xfe,
				0xc6, 0x70, 0xa4, 0x1a, 0xe4, 0x76, 0x7d, 0xac,
			}),
		},
		PublicKeyAlgorithm: x509.ECDSA,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Signature: []byte{
			0x30, 0x44, 0x02, 0x20, 0x66, 0x0c, 0xfd, 0x81,
			0xdc, 0x7d, 0x8a, 0x73, 0xa9, 0xe9, 0xb4, 0x97,
			0xe0, 0x49, 0x18, 0x89, 0x40, 0xb2, 0x2d, 0x5f,
			0x71, 0x1a, 0xf6, 0x9b, 0xa2, 0xfb, 0xb9, 0x0b,
			0xd5, 0x24, 0x46, 0xbf, 0x02, 0x20, 0x11, 0x81,
			0x6e, 0x4a, 0x74, 0x97, 0x8b, 0x5e, 0xb0, 0x02,
			0xa8, 0x5d, 0xe9, 0x6c, 0x2f, 0x28, 0x09, 0x8c,
			0xfb, 0x94, 0x19, 0x12, 0xca, 0xf8, 0xeb, 0x5d,
			0x8c, 0xf0, 0x48, 0x37, 0x56, 0x68,
		},
	}
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    *x509.CertificateRequest
		wantErr bool
	}{
		{"ok", args{"testdata/test.csr"}, expected, false},
		{"ok der", args{"testdata/test.der"}, expected, false},
		{"ok keytool", args{"testdata/keytool.csr"}, expected, false},
		{"fail missing", args{"testdata/missing.csr"}, nil, true},
		{"fail bad csr", args{"testdata/bad.csr"}, nil, true},
		{"fail certificate", args{"testdata/ca.crt"}, nil, true},
		{"fail certificate der", args{"testdata/ca.der"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadCertificateRequest(tt.args.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Cleanup raw data
			if got != nil {
				got.Raw = nil
				got.RawSubject = nil
				got.RawSubjectPublicKeyInfo = nil
				got.RawTBSCertificateRequest = nil
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadCertificateRequest() = \n%#v, want \n%#v", got, tt.want)
			}
		})
	}
}

func TestBundleCertificate(t *testing.T) {
	tests := []struct {
		name   string
		bundle string
		certs  []string
		added  bool
		err    error
	}{
		{"append", "testdata/bundle.crt", []string{"testdata/ca.crt"}, true, nil},
		{"two", "testdata/bundle.crt", []string{"testdata/ca.crt", "testdata/ca2.crt"}, true, nil},
		{"none", "testdata/bundle.crt", nil, false, nil},
		{"found", "testdata/ca.crt", []string{"testdata/ca.crt"}, false, nil},
		{"bad cert", "testdata/bundle.crt", []string{"testdata/badca.crt"}, false, errors.New("invalid certificate 0")},
		{"bad bundle", "testdata/badca.crt", []string{"testdata/ca.crt"}, false, errors.New("invalid bundle")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundlePEM, err := os.ReadFile(tc.bundle)
			if err != nil {
				t.Fatal(err)
			}
			certsPEM := make([][]byte, len(tc.certs))
			for i, fn := range tc.certs {
				certsPEM[i], err = os.ReadFile(fn)
				if err != nil {
					t.Fatal(err)
				}
			}

			got, added, err := BundleCertificate(bundlePEM, certsPEM...)
			if tc.err != nil {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.added, added)
				if added {
					assert.NotEqual(t, bundlePEM, got)
				} else {
					assert.Equal(t, bundlePEM, got)
				}
			}
		})
	}
}

func TestUnbundleCertificate(t *testing.T) {
	tests := []struct {
		name       string
		bundle     string
		certs      []string
		wantBundle string
		modified   bool
		err        error
	}{
		{"remove one leave one", "testdata/bundle.crt", []string{"testdata/bundle-1st.crt"}, "testdata/bundle-2nd.crt", true, nil},
		{"remove two leave none", "testdata/bundle.crt", []string{"testdata/bundle-1st.crt", "testdata/bundle-2nd.crt"}, "", true, nil},
		{"remove none", "testdata/bundle.crt", []string{"testdata/ca.crt"}, "testdata/bundle.crt", false, nil},
		{"none to remove", "testdata/bundle.crt", []string{}, "testdata/bundle.crt", false, nil},
		{"remove bundle", "testdata/bundle.crt", []string{"testdata/bundle.crt"}, "", true, nil},
		{"bad cert", "testdata/bundle.crt", []string{"testdata/badca.crt"}, "", false, errors.New("invalid certificate 0")},
		{"bad bundle", "testdata/badca.crt", []string{"testdata/ca.crt"}, "", false, errors.New("invalid bundle")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundlePEM, err := os.ReadFile(tc.bundle)
			if err != nil {
				t.Fatal(err)
			}
			certsPEM := make([][]byte, len(tc.certs))
			for i, fn := range tc.certs {
				certsPEM[i], err = os.ReadFile(fn)
				if err != nil {
					t.Fatal(err)
				}
			}

			got, modified, err := UnbundleCertificate(bundlePEM, certsPEM...)
			if tc.err != nil {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.modified, modified)
				if tc.wantBundle == "" {
					assert.Nil(t, got)
				} else {
					want, err := os.ReadFile(tc.wantBundle)
					if err != nil {
						t.Fatal(err)
					}
					assert.Equal(t, strings.TrimSpace(string(want)), strings.TrimSpace(string(got)))
				}
			}
		})
	}
}
