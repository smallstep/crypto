package jose

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"os"
	"testing"

	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
)

var (
	badCertFile = "./testdata/bad-rsa.crt"
	badKeyFile  = "./testdata/bad-rsa.key"
	certFile    = "./testdata/rsa2048.crt"
	keyFile     = "./testdata/rsa2048.key"
)

func TestValidateSSHPOP(t *testing.T) {
	key, err := pemutil.Read("testdata/host-key")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("testdata/host-key-cert.pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := bytes.Fields(b)
	if len(fields) != 3 {
		t.Fatalf("unexpected number of fields, got = %d, want 3", len(fields))
	}
	certBase64 := string(fields[1])

	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		certFile string
		key      interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok crypto.PrivateKey", args{"testdata/host-key-cert.pub", key}, certBase64, false},
		{"ok JSONWebKey", args{"testdata/host-key-cert.pub", &JSONWebKey{Key: key}}, certBase64, false},
		{"ok OpaqueSigner", args{"testdata/host-key-cert.pub", NewOpaqueSigner(key.(crypto.Signer))}, certBase64, false},
		{"fail certFile", args{"", key}, "", true},
		{"fail missing", args{"testdata/missing", key}, "", true},
		{"fail not ssh", args{"testdata/rsa2048.crt", key}, "", true},
		{"fail not a cert", args{"testdata/host-key.pub", key}, "", true},
		{"fail validate crypto.PrivateKey", args{"testdata/host-key-cert.pub", otherKey}, "", true},
		{"fail validate JSONWebKey", args{"testdata/host-key-cert.pub", &JSONWebKey{Key: otherKey}}, "", true},
		{"fail validate OpaqueSigner", args{"testdata/host-key-cert.pub", NewOpaqueSigner(otherKey)}, "", true},
		{"fail bad key", args{"testdata/host-key-cert.pub", "not a key"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateSSHPOP(tt.args.certFile, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSSHPOP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateSSHPOP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validateX5(t *testing.T) {
	type test struct {
		certs []*x509.Certificate
		key   interface{}
		err   error
	}
	tests := map[string]func() test{
		"fail/empty-certs": func() test {
			return test{
				certs: []*x509.Certificate{},
				key:   nil,
				err:   errors.New("certs cannot be empty"),
			}
		},
		"fail/bad-key": func() test {
			certs, err := pemutil.ReadCertificateBundle(certFile)
			assert.FatalError(t, err)
			return test{
				certs: certs,
				key:   nil,
				err:   errors.New("error verifying certificate and key"),
			}
		},
		"fail/cert-not-approved-for-digital-signature": func() test {
			certs, err := pemutil.ReadCertificateBundle(badCertFile)
			assert.FatalError(t, err)
			k, err := pemutil.Read(badKeyFile)
			assert.FatalError(t, err)
			return test{
				certs: certs,
				key:   k,
				err: errors.New("certificate/private-key pair used to sign " +
					"token is not approved for digital signature"),
			}
		},
		"ok": func() test {
			certs, err := pemutil.ReadCertificateBundle(certFile)
			assert.FatalError(t, err)
			k, err := pemutil.Read(keyFile)
			assert.FatalError(t, err)
			return test{
				certs: certs,
				key:   k,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if err := validateX5(tc.certs, tc.key); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
			}
		})
	}
}

func TestValidateX5T(t *testing.T) {
	type test struct {
		certs []*x509.Certificate
		key   interface{}
		fp    string
		err   error
	}
	tests := map[string]func() test{
		"fail/validateX5-error": func() test {
			return test{
				certs: []*x509.Certificate{},
				key:   nil,
				err:   errors.New("ValidateX5T: certs cannot be empty"),
			}
		},
		"ok": func() test {
			certs, err := pemutil.ReadCertificateBundle(certFile)
			assert.FatalError(t, err)
			k, err := pemutil.Read(keyFile)
			assert.FatalError(t, err)
			cert, err := pemutil.ReadCertificate(certFile)
			assert.FatalError(t, err)
			// x5t is the base64 URL encoded SHA1 thumbprint
			// (see https://tools.ietf.org/html/rfc7515#section-4.1.7)
			// nolint:gosec // RFC 7515 - X.509 Certificate SHA-1 Thumbprint
			fp := sha1.Sum(cert.Raw)
			return test{
				certs: certs,
				key:   k,
				fp:    base64.URLEncoding.EncodeToString(fp[:]),
			}
		},
		"ok/opaque": func() test {
			certs, err := pemutil.ReadCertificateBundle(certFile)
			assert.FatalError(t, err)
			k, err := pemutil.Read(keyFile)
			assert.FatalError(t, err)
			sig, ok := k.(crypto.Signer)
			assert.True(t, ok)
			op := NewOpaqueSigner(sig)
			cert, err := pemutil.ReadCertificate(certFile)
			assert.FatalError(t, err)
			// x5t is the base64 URL encoded SHA1 thumbprint
			// (see https://tools.ietf.org/html/rfc7515#section-4.1.7)
			// nolint:gosec // RFC 7515 - X.509 Certificate SHA-1 Thumbprint
			fp := sha1.Sum(cert.Raw)
			return test{
				certs: certs,
				key:   op,
				fp:    base64.URLEncoding.EncodeToString(fp[:]),
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if fingerprint, err := ValidateX5T(tc.certs, tc.key); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
				assert.Equals(t, tc.fp, fingerprint)
			}
		})
	}
}

func TestValidateX5C(t *testing.T) {
	type test struct {
		certs []*x509.Certificate
		key   interface{}
		err   error
	}
	tests := map[string]func() test{
		"fail/validateX5-error": func() test {
			return test{
				certs: []*x509.Certificate{},
				key:   nil,
				err:   errors.New("ValidateX5C: certs cannot be empty"),
			}
		},
		"ok": func() test {
			certs, err := pemutil.ReadCertificateBundle(certFile)
			assert.FatalError(t, err)
			k, err := pemutil.Read(keyFile)
			assert.FatalError(t, err)
			return test{
				certs: certs,
				key:   k,
			}
		},
		"ok/opaque": func() test {
			certs, err := pemutil.ReadCertificateBundle(certFile)
			assert.FatalError(t, err)
			k, err := pemutil.Read(keyFile)
			assert.FatalError(t, err)
			sig, ok := k.(crypto.Signer)
			assert.True(t, ok)
			op := NewOpaqueSigner(sig)
			return test{
				certs: certs,
				key:   op,
			}
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			tc := run()
			if certs, err := ValidateX5C(tc.certs, tc.key); err != nil {
				if assert.NotNil(t, tc.err) {
					assert.HasPrefix(t, err.Error(), tc.err.Error())
				}
			} else {
				assert.Nil(t, tc.err)
				assert.Equals(t, []string{`MIIDCTCCAfGgAwIBAgIQIdY8a5pFZ/FGUowvuGdJvTANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwR0ZXN0MB4XDTIwMDQyMTA0MDg0MFoXDTIwMDQyMjA0MDg0MFowDzENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0zsTneONS0eNto7LMlD8GtcUYXqILSEWD07v0HgbIguBT+yC8BozpAT3lyB+oBBZkFLzfEHAteULngPwlq0R5hsEZJ6lcL1Z9WXwyLE4nkEndIPMA+zQmHnOzoqgKy7pIqUnFqSGXtGp384fFF3Y0/qjeFciLnmf+Wn0PneaToY1rDj2Eb9sFf5UDiVaSLT1NzpSyXOS5uGbGplPe+WE8uEb3u3Vg2VGbEPau2l5MPYroCwSyxqlpKsmzJ558uvjQ7KpRExSNdb6f0iRfdRMbw3LahrxhbKV1mmM6GD5onmbgBCZpw5htOJj1MzVFZOdnoTHmMl/Y/IUdMjv0jG/UCAwEAAaNhMF8wDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUXlQCQL6RymQZnvqY15F/GlE3H4UwDwYDVR0RBAgwBoIEdGVzdDANBgkqhkiG9w0BAQsFAAOCAQEArVmOL5L+NVsnCcUWfOVXQYg/6P8AGdPJBECk+BE5pbtMg0GuH5Ml/vCTBqD+diWC4O0TZDxPMhXH5Ehl+67hcqeu4riwB2WvvKOlAqHqIuqVDRHtxwknvS1efstBKVdDC6aAfIa5f2dmCSxvd8elpcnufEefLGALTSPxg4uMVvpfWUkkmpmvOUpI3gNrlvP2H4KZk7hKYz+J4x2jv2pdPWUAtt1U4M8oQ4BCPrrHSxznw2Q5mdCMIB64ZeYnZ+rAMQS6WnZy1fTC3d0pCs0UCXH5JefBpha1clqHDUkxHA6/1EYYsSlKGFaPEmfv2uw7MFz0o+yntG34KVdsC8HO3g==`}, certs)
			}
		})
	}
}

func TestValidateJWK_sig(t *testing.T) {
	mustSigner := func(kty, crv string, size int) crypto.Signer {
		signer, err := keyutil.GenerateSigner(kty, crv, size)
		if err != nil {
			t.Fatal(err)
		}
		return signer
	}

	rsaKey := mustSigner("RSA", "", 2048)
	p256Key := mustSigner("EC", "P-256", 0)
	p384key := mustSigner("EC", "P-384", 0)
	p521Key := mustSigner("EC", "P-521", 0)
	edKey := mustSigner("OKP", "Ed25519", 0)

	type args struct {
		jwk *JSONWebKey
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok ES256", args{&JSONWebKey{Use: "sig", Algorithm: ES256, Key: p256Key}}, false},
		{"ok ES384", args{&JSONWebKey{Use: "sig", Algorithm: ES384, Key: p384key}}, false},
		{"ok ES512", args{&JSONWebKey{Use: "sig", Algorithm: ES512, Key: p521Key}}, false},
		{"ok ES256 pub", args{&JSONWebKey{Use: "sig", Algorithm: ES256, Key: p256Key.Public()}}, false},
		{"ok ES384 pub", args{&JSONWebKey{Use: "sig", Algorithm: ES384, Key: p384key.Public()}}, false},
		{"ok ES512 pub", args{&JSONWebKey{Use: "sig", Algorithm: ES512, Key: p521Key.Public()}}, false},
		{"ok RS256", args{&JSONWebKey{Use: "sig", Algorithm: RS256, Key: rsaKey}}, false},
		{"ok RS384", args{&JSONWebKey{Use: "sig", Algorithm: RS384, Key: rsaKey.Public()}}, false},
		{"ok RS512", args{&JSONWebKey{Use: "sig", Algorithm: RS512, Key: rsaKey}}, false},
		{"ok PS256", args{&JSONWebKey{Use: "sig", Algorithm: PS256, Key: rsaKey.Public()}}, false},
		{"ok PS384", args{&JSONWebKey{Use: "sig", Algorithm: PS384, Key: rsaKey}}, false},
		{"ok PS512", args{&JSONWebKey{Use: "sig", Algorithm: PS512, Key: rsaKey.Public()}}, false},
		{"ok EdDSA", args{&JSONWebKey{Use: "sig", Algorithm: EdDSA, Key: edKey}}, false},
		{"ok EdDSA pub", args{&JSONWebKey{Use: "sig", Algorithm: EdDSA, Key: edKey.Public()}}, false},
		{"ok HS256", args{&JSONWebKey{Use: "sig", Algorithm: HS256, Key: []byte("raw-key")}}, false},
		{"ok HS384", args{&JSONWebKey{Use: "sig", Algorithm: HS384, Key: []byte("raw-key")}}, false},
		{"ok HS512", args{&JSONWebKey{Use: "sig", Algorithm: HS512, Key: []byte("raw-key")}}, false},
		{"ok OpaqueSigner", args{&JSONWebKey{Use: "sig", Algorithm: ES256, Key: NewOpaqueSigner(p256Key)}}, false},
		{"fail alg empty", args{&JSONWebKey{Use: "sig", Key: p256Key}}, true},
		{"fail ECDSA", args{&JSONWebKey{Use: "sig", Algorithm: ES384, Key: p256Key}}, true},
		{"fail ECDSA pub", args{&JSONWebKey{Use: "sig", Algorithm: ES384, Key: p256Key.Public()}}, true},
		{"fail RSA", args{&JSONWebKey{Use: "sig", Algorithm: ES256, Key: rsaKey}}, true},
		{"fail Ed25519", args{&JSONWebKey{Use: "sig", Algorithm: ES256, Key: edKey}}, true},
		{"fail bytes", args{&JSONWebKey{Use: "sig", Algorithm: ES256, Key: []byte("raw-key")}}, true},
		{"fail OpaqueSigner", args{&JSONWebKey{Use: "sig", Algorithm: RS256, Key: p256Key}}, true},
		{"fail unknown", args{&JSONWebKey{Use: "sig", Algorithm: HS256, Key: "raw-key"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateJWK(tt.args.jwk); (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWK() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
