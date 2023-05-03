package keyutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/smallstep/assert"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/ssh"
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
	testSSHPub    = `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFqJfS311sNwYHqZQXSkOTiAqId6jcgX+qIiG/23m/6UxaksvOilHvhOGOUkpRM9paoO/ViKLGYJB20gbJlO4Ro= jane@doe.com`
	testSSHCert   = `ecdsa-sha2-nistp256-cert-v01@openssh.com AAAAKGVjZHNhLXNoYTItbmlzdHAyNTYtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgKWZGQ1gramJ1ayV7UiNJLmE5PGMpRjEoIjI6Jz9GUmUAAAAIbmlzdHAyNTYAAABBBFqJfS311sNwYHqZQXSkOTiAqId6jcgX+qIiG/23m/6UxaksvOilHvhOGOUkpRM9paoO/ViKLGYJB20gbJlO4RqCjePcANhGLAAAAAEAAAAMamFuZUBkb2UuY29tAAAAEQAAAARqYW5lAAAABWFkbWluAAAAAF80Q9gAAAAAXzUlFAAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMopHG2SUfV6NXyLKrSGkUyFJ8Zp8zFY+3wilPruczJbxY0kSAcr+cwfppEmO6SsPcClXcy59lx71eSDdGURqv8AAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIQCrKn7AJCX88hCZr1e3zfKZf18GmU2Rvqvmd0XKsl9J5gAAACAj2mnrgq0ScI4foEGv3gxglehBhrev02sqjiRchty7Pg== jane@doe.com`
	testSSHPubPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWol9LfXWw3BgeplBdKQ5OICoh3qN
yBf6oiIb/beb/pTFqSy86KUe+E4Y5SSlEz2lqg79WIosZgkHbSBsmU7hGg==
-----END PUBLIC KEY-----`
)

type badSSHPublicKey struct{}

func (k *badSSHPublicKey) Type() string                                 { return "foo" }
func (k *badSSHPublicKey) Marshal() []byte                              { return []byte("bar") }
func (k *badSSHPublicKey) Verify(data []byte, sig *ssh.Signature) error { return nil }

func must(args ...interface{}) interface{} {
	if err := args[len(args)-1]; err != nil {
		panic(err)
	}
	return args[0]
}

var randReader = rand.Reader

func cleanupRandReader(t *testing.T) {
	rr := rand.Reader
	t.Cleanup(func() {
		rand.Reader = rr
	})
}

type zeroReader struct{}

func (zeroReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = 0
	}
	return len(buf), nil
}

type eofReader struct{}

func (eofReader) Read(buf []byte) (int, error) {
	return 0, io.EOF
}

func verifyKeyPair(h crypto.Hash, priv, pub interface{}) error {
	s, ok := priv.(crypto.Signer)
	if !ok {
		return fmt.Errorf("type %T is not a crypto.Signer", priv)
	}

	var sum []byte
	if h == crypto.Hash(0) {
		sum = []byte("a message")
	} else {
		sum = h.New().Sum([]byte("a message"))
	}
	sig, err := s.Sign(randReader, sum, h)
	if err != nil {
		return fmt.Errorf("%T.Sign() error = %w", s, err)
	}

	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(p, sum, sig) {
			return fmt.Errorf("ecdsa.VerifyASN1 failed")
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(p, h, sig, sum); err != nil {
			return fmt.Errorf("rsa.VerifyPKCS1v15 failed")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(p, sum, sig) {
			return fmt.Errorf("ed25519.Verify failed")
		}
	case x25519.PublicKey:
		if !x25519.Verify(p, sum, sig) {
			return fmt.Errorf("x25519.Verify failed")
		}
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}

	return nil
}

func verifyPrivateKey(h crypto.Hash, priv interface{}) error {
	s, ok := priv.(crypto.Signer)
	if !ok {
		return fmt.Errorf("type %T is not a crypto.Signer", priv)
	}

	return verifyKeyPair(h, priv, s.Public())
}

func TestPublicKey(t *testing.T) {
	type opaqueSigner struct {
		crypto.Signer
	}
	ecdsaKey := must(generateECKey("P-256")).(*ecdsa.PrivateKey)
	ecdsaSigner := opaqueSigner{ecdsaKey}
	rsaKey := must(generateRSAKey(2048)).(*rsa.PrivateKey)
	ed25519Key := must(generateOKPKey("Ed25519")).(ed25519.PrivateKey)
	x25519Pub, x25519Priv, err := x25519.GenerateKey(rand.Reader)
	assert.FatalError(t, err)

	type args struct {
		priv interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ecdsa", args{ecdsaKey}, ecdsaKey.Public(), false},
		{"ecdsaPublic", args{&ecdsaKey.PublicKey}, ecdsaKey.Public(), false},
		{"rsa", args{rsaKey}, rsaKey.Public(), false},
		{"rsaPublic", args{&rsaKey.PublicKey}, rsaKey.Public(), false},
		{"ed25519", args{ed25519Key}, ed25519Key.Public(), false},
		{"ed25519Public", args{ed25519.PublicKey(ed25519Key[32:])}, ed25519Key.Public(), false},
		{"x25519", args{x25519Priv}, x25519Pub, false},
		{"x25519Public", args{x25519Pub}, x25519Pub, false},
		{"ecdsaSigner", args{ecdsaSigner}, ecdsaKey.Public(), false},
		{"fail", args{[]byte("octkey")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PublicKey(tt.args.priv)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateDefaultKey(t *testing.T) {
	cleanupRandReader(t)

	tests := []struct {
		name      string
		rr        io.Reader
		assertion func(t *testing.T, got interface{})
		wantErr   bool
	}{
		{"ok", randReader, func(t *testing.T, got interface{}) {
			t.Helper()
			if err := verifyPrivateKey(crypto.SHA256, got); err != nil {
				t.Errorf("GenerateDefaultKey() error = %v", err)
			}
		}, false},
		{"eof", eofReader{}, func(t *testing.T, got interface{}) {
			if !reflect.DeepEqual(got, nil) {
				t.Errorf("GenerateDefaultKey() got = %v, want nil", got)
			}
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rand.Reader = tt.rr
			got, err := GenerateDefaultKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDefaultKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.assertion(t, got)
		})
	}
}

func TestGenerateDefaultKeyPair(t *testing.T) {
	cleanupRandReader(t)

	assertKey := func(h crypto.Hash) func(t *testing.T, got, got1 interface{}) {
		return func(t *testing.T, got, got1 interface{}) {
			t.Helper()
			if err := verifyKeyPair(h, got1, got); err != nil {
				t.Errorf("GenerateDefaultKeyPair() error = %v", err)
			}
		}
	}

	assertNil := func() func(t *testing.T, got, got1 interface{}) {
		return func(t *testing.T, got, got1 interface{}) {
			t.Helper()
			if !reflect.DeepEqual(got, nil) {
				t.Errorf("GenerateDefaultKeyPair() got = %v, want nil", got)
			}
			if !reflect.DeepEqual(got1, nil) {
				t.Errorf("GenerateDefaultKeyPair() got1 = %v, want nil", got1)
			}
		}
	}

	tests := []struct {
		name      string
		rr        io.Reader
		assertion func(t *testing.T, got, got1 interface{})
		wantErr   bool
	}{
		{"ok", randReader, assertKey(crypto.SHA256), false},
		{"eof", eofReader{}, assertNil(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rand.Reader = tt.rr
			got, got1, err := GenerateDefaultKeyPair()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDefaultKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.assertion(t, got, got1)
		})
	}
}

func TestGenerateKey(t *testing.T) {
	cleanupRandReader(t)

	assertKey := func(t *testing.T, h crypto.Hash, key interface{}) {
		t.Helper()
		if err := verifyPrivateKey(h, key); err != nil {
			t.Errorf("GenerateKey() error = %v", err)
		}
	}

	octKey := make([]byte, 32)
	for i := range octKey {
		octKey[i] = 'a'
	}
	assertOCT := func(t *testing.T, h crypto.Hash, key interface{}) {
		t.Helper()
		if !reflect.DeepEqual(key, octKey) {
			t.Errorf("GenerateKey() got = %v, want %v", key, octKey)
		}
	}

	type args struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name    string
		rr      io.Reader
		args    args
		assert  func(t *testing.T, h crypto.Hash, key interface{})
		hash    crypto.Hash
		wantErr bool
	}{
		{"P-256", randReader, args{"EC", "P-256", 0}, assertKey, crypto.SHA256, false},
		{"P-384", randReader, args{"EC", "P-384", 0}, assertKey, crypto.SHA384, false},
		{"P-521", randReader, args{"EC", "P-521", 0}, assertKey, crypto.SHA512, false},
		{"Ed25519", randReader, args{"OKP", "Ed25519", 0}, assertKey, crypto.Hash(0), false},
		{"X25519", randReader, args{"OKP", "X25519", 0}, assertKey, crypto.Hash(0), false},
		{"OCT", zeroReader{}, args{"oct", "", 32}, assertOCT, crypto.Hash(0), false},
		{"eof EC", eofReader{}, args{"EC", "P-256", 0}, nil, 0, true},
		{"eof RSA", eofReader{}, args{"RSA", "", 1024}, nil, 0, true},
		{"eof Ed25519", eofReader{}, args{"OKP", "Ed25519", 0}, nil, 0, true},
		{"eof X25519", eofReader{}, args{"OKP", "X25519", 0}, nil, 0, true},
		{"eof oct", eofReader{}, args{"oct", "", 32}, nil, 0, true},
		{"unknown EC curve", randReader, args{"EC", "P-128", 0}, nil, 0, true},
		{"unknown OKP curve", randReader, args{"OKP", "Edward", 0}, nil, 0, true},
		{"unknown type", randReader, args{"FOO", "", 1024}, nil, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rand.Reader = tt.rr
			got, err := GenerateKey(tt.args.kty, tt.args.crv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				tt.assert(t, tt.hash, got)
			}
		})
	}
}

func TestGenerateKey_rsa(t *testing.T) {
	type args struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name     string
		args     args
		wantType reflect.Type
		wantErr  bool
	}{
		{"RSA2048", args{"RSA", "", 2048}, reflect.TypeOf(&rsa.PrivateKey{}), false},
		{"RSA3072", args{"RSA", "", 3072}, reflect.TypeOf(&rsa.PrivateKey{}), false},
		{"fail", args{"RSA", "", 1}, nil, true},
		{"fail size", args{"RSA", "", 1024}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get rid of size validation for coverage purposes.
			if tt.args.size == 1 {
				tmp := MinRSAKeyBytes
				MinRSAKeyBytes = 0
				t.Cleanup(func() {
					MinRSAKeyBytes = tmp
				})
			}
			got, err := GenerateKey(tt.args.kty, tt.args.crv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reflect.TypeOf(got) != tt.wantType {
				t.Errorf("GenerateKey() = %v, want %v", got, tt.wantType)
			}
			if k, ok := got.(*rsa.PrivateKey); ok {
				if k.Size() != tt.args.size/8 {
					t.Errorf("GenerateKey() size = %d, want %d", k.Size(), tt.args.size/8)
				}
			}
		})
	}
}

func TestGenerateKeyPair(t *testing.T) {
	cleanupRandReader(t)

	assertKey := func(h crypto.Hash) func(t *testing.T, got, got1 interface{}) {
		return func(t *testing.T, got, got1 interface{}) {
			t.Helper()
			if err := verifyKeyPair(h, got1, got); err != nil {
				t.Errorf("GenerateKeyPair() error = %v", err)
			}
		}
	}

	assertNil := func() func(t *testing.T, got, got1 interface{}) {
		return func(t *testing.T, got, got1 interface{}) {
			t.Helper()
			if !reflect.DeepEqual(got, nil) {
				t.Errorf("GenerateKeyPair() got = %v, want nil", got)
			}
			if !reflect.DeepEqual(got1, nil) {
				t.Errorf("GenerateKeyPair() got1 = %v, want nil", got1)
			}
		}
	}

	type args struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name      string
		rr        io.Reader
		args      args
		assertion func(t *testing.T, got, got1 interface{})
		wantErr   bool
	}{
		{"P-256", randReader, args{"EC", "P-256", 0}, assertKey(crypto.SHA256), false},
		{"P-384", randReader, args{"EC", "P-384", 0}, assertKey(crypto.SHA384), false},
		{"P-521", randReader, args{"EC", "P-521", 0}, assertKey(crypto.SHA512), false},
		{"Ed25519", randReader, args{"OKP", "Ed25519", 0}, assertKey(crypto.Hash(0)), false},
		{"OCT", zeroReader{}, args{"oct", "", 32}, assertNil(), true},
		{"eof", eofReader{}, args{"EC", "P-256", 0}, assertNil(), true},
		{"unknown", randReader, args{"EC", "P-128", 0}, assertNil(), true},
		{"unknown", randReader, args{"FOO", "", 1024}, assertNil(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rand.Reader = tt.rr
			got, got1, err := GenerateKeyPair(tt.args.kty, tt.args.crv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.assertion(t, got, got1)
		})
	}
}

func TestGenerateKeyPair_rsa(t *testing.T) {
	pubType := reflect.TypeOf(&rsa.PublicKey{})
	privType := reflect.TypeOf(&rsa.PrivateKey{})

	type args struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name      string
		args      args
		wantType  reflect.Type
		wantType1 reflect.Type
		wantErr   bool
	}{
		{"RSA2048", args{"RSA", "", 2048}, pubType, privType, false},
		{"RSA3072", args{"RSA", "", 3072}, pubType, privType, false},
		{"fail", args{"RSA", "", 1024}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := GenerateKeyPair(tt.args.kty, tt.args.crv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reflect.TypeOf(got) != tt.wantType {
				t.Errorf("GenerateKey() = %v, want %v", got, tt.wantType)
			}
			if reflect.TypeOf(got1) != tt.wantType1 {
				t.Errorf("GenerateKey() = %v, want %v", got, tt.wantType)
			}
			if k, ok := got.(*rsa.PublicKey); ok {
				if k.Size() != tt.args.size/8 {
					t.Errorf("GenerateKey() size = %d, want %d", k.Size(), tt.args.size/8)
				}
			}
			if k, ok := got1.(*rsa.PrivateKey); ok {
				if k.Size() != tt.args.size/8 {
					t.Errorf("GenerateKey() size = %d, want %d", k.Size(), tt.args.size/8)
				}
			}
		})
	}
}

func TestGenerateDefaultSigner(t *testing.T) {
	cleanupRandReader(t)

	tests := []struct {
		name      string
		rr        io.Reader
		assertion func(t *testing.T, got crypto.Signer)
		wantErr   bool
	}{
		{"ok", randReader, func(t *testing.T, got crypto.Signer) {
			t.Helper()
			if err := verifyPrivateKey(crypto.SHA256, got); err != nil {
				t.Errorf("GenerateDefaultSigner() error = %v", err)
			}
		}, false},
		{"eof", eofReader{}, func(t *testing.T, got crypto.Signer) {
			if !reflect.DeepEqual(got, nil) {
				t.Errorf("GenerateDefaultSigner() got = %v, want nil", got)
			}
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rand.Reader = tt.rr
			got, err := GenerateDefaultSigner()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDefaultSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.assertion(t, got)
		})
	}
}

func TestGenerateSigner(t *testing.T) {
	assertSigner := func(h crypto.Hash) func(t *testing.T, got crypto.Signer) {
		return func(t *testing.T, got crypto.Signer) {
			t.Helper()
			if err := verifyPrivateKey(h, got); err != nil {
				t.Errorf("GenerateSigner() error = %v", err)
			}
		}
	}
	assertNil := func() func(t *testing.T, got crypto.Signer) {
		return func(t *testing.T, got crypto.Signer) {
			t.Helper()
			if !reflect.DeepEqual(got, nil) {
				t.Errorf("GenerateSigner() got = %v, want nil", got)
			}
		}
	}

	type args struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name      string
		args      args
		assertion func(t *testing.T, got crypto.Signer)
		wantErr   bool
	}{
		{"P-256", args{"EC", "P-256", 0}, assertSigner(crypto.SHA256), false},
		{"P-384", args{"EC", "P-384", 0}, assertSigner(crypto.SHA384), false},
		{"P-521", args{"EC", "P-521", 0}, assertSigner(crypto.SHA512), false},
		{"Ed25519", args{"OKP", "Ed25519", 0}, assertSigner(crypto.Hash(0)), false},
		{"OCT", args{"oct", "", 32}, assertNil(), true},
		{"unknown", args{"EC", "P-128", 0}, assertNil(), true},
		{"unknown", args{"FOO", "", 1024}, assertNil(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateSigner(tt.args.kty, tt.args.crv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.assertion(t, got)
		})
	}
}

func TestExtractKey(t *testing.T) {
	rsaKey := must(generateRSAKey(2048)).(*rsa.PrivateKey)
	ecKey := must(generateECKey("P-256")).(*ecdsa.PrivateKey)
	edKey := must(generateOKPKey("Ed25519")).(ed25519.PrivateKey)
	octKey := must(generateOctKey(64)).([]byte)

	b, _ := pem.Decode([]byte(testCRT))
	cert, err := x509.ParseCertificate(b.Bytes)
	assert.FatalError(t, err)

	b, _ = pem.Decode([]byte(testCSR))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	assert.FatalError(t, err)

	b, _ = pem.Decode([]byte(testSSHPubPEM))
	sshKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	assert.FatalError(t, err)

	sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testSSHPub))
	assert.FatalError(t, err)

	sshCert, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testSSHCert))
	assert.FatalError(t, err)

	type args struct {
		in interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    interface{}
		wantErr bool
	}{
		{"RSA private key", args{rsaKey}, rsaKey, false},
		{"RSA public key", args{rsaKey.Public()}, rsaKey.Public(), false},
		{"EC private key", args{ecKey}, ecKey, false},
		{"EC public key", args{ecKey.Public()}, ecKey.Public(), false},
		{"OKP private key", args{edKey}, edKey, false},
		{"OKP public key", args{edKey.Public()}, edKey.Public(), false},
		{"oct key", args{octKey}, octKey, false},
		{"certificate", args{cert}, cert.PublicKey, false},
		{"csr", args{csr}, csr.PublicKey, false},
		{"ssh public key", args{sshPub}, sshKey, false},
		{"ssh cert", args{sshCert}, sshKey, false},
		{"fail string", args{"fooo"}, nil, true},
		{"fail bad ssh.Certificate.Key", args{&ssh.Certificate{Key: new(badSSHPublicKey)}}, nil, true},
		{"fail bad ssh.PublicKey", args{new(badSSHPublicKey)}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractKey(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ExtractKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyPair(t *testing.T) {
	ecdsaKey := must(generateECKey("P-256")).(*ecdsa.PrivateKey)
	rsaKey := must(generateRSAKey(2048)).(*rsa.PrivateKey)
	ed25519Key := must(generateOKPKey("Ed25519")).(ed25519.PrivateKey)

	ecdsaKey1 := must(generateECKey("P-256")).(*ecdsa.PrivateKey)
	rsaKey1 := must(generateRSAKey(2048)).(*rsa.PrivateKey)
	ed25519Key1 := must(generateOKPKey("Ed25519")).(ed25519.PrivateKey)

	type args struct {
		pubkey interface{}
		key    interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ecdsa", args{ecdsaKey.Public(), ecdsaKey}, false},
		{"rsa", args{rsaKey.Public(), rsaKey}, false},
		{"ed25519", args{ed25519Key.Public(), ed25519Key}, false},
		// wrong private type
		{"fail ecdsa", args{ecdsaKey.Public(), ecdsaKey.Public()}, true},
		{"fail rsa", args{rsaKey.Public(), rsaKey.Public()}, true},
		{"fail ed25519", args{ed25519Key.Public(), ed25519Key.Public()}, true},
		// wrong private key
		{"fail ecdsa key", args{ecdsaKey.Public(), ecdsaKey1}, true},
		{"fail rsa key", args{rsaKey.Public(), rsaKey1}, true},
		{"fail ed25519 key", args{ed25519Key.Public(), ed25519Key1}, true},
		// wrong public type
		{"fail type", args{[]byte("foo"), []byte("foo")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyPair(tt.args.pubkey, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("VerifyPair() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestInsecure(t *testing.T) {
	tests := []struct {
		name    string
		run     func(t *testing.T) error
		wantErr bool
	}{
		{"ok RSA 2048", func(t *testing.T) (err error) {
			_, err = GenerateKey("RSA", "", 2048)
			return
		}, false},
		{"fail RSA 1024", func(t *testing.T) (err error) {
			_, err = GenerateKey("RSA", "", 1024)
			return
		}, true},
		{"ok RSA 2048 insecure", func(t *testing.T) (err error) {
			revert := Insecure()
			t.Cleanup(revert)
			_, err = GenerateKey("RSA", "", 2048)
			return
		}, false},
		{"ok RSA 1024 insecure", func(t *testing.T) (err error) {
			revert := Insecure()
			t.Cleanup(revert)
			_, err = GenerateKey("RSA", "", 1024)
			return
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run(t)
			if (err != nil) != tt.wantErr {
				t.Errorf("Insecure() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestEqual(t *testing.T) {
	mustSigner := func(kty, crv string, size int) crypto.Signer {
		s, err := GenerateSigner(kty, crv, size)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	mustCopy := func(key crypto.Signer) crypto.Signer {
		if x, ok := key.(x25519.PrivateKey); ok {
			return x25519.PrivateKey([]byte(x))
		}

		b, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			t.Fatal(err)
		}
		signer, ok := priv.(crypto.Signer)
		if !ok {
			t.Fatalf("type %T is not a crypto.Signer", priv)
		}
		return signer
	}

	ecdsaKey := mustSigner("EC", "P-256", 0)
	rsaKey := mustSigner("RSA", "", 2048)
	ed25519Key := mustSigner("OKP", "Ed25519", 0)
	x25519Key := mustSigner("OKP", "X25519", 0)

	type args struct {
		x any
		y any
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"ok ecdsaKey", args{ecdsaKey, mustCopy(ecdsaKey)}, true},
		{"ok rsaKey", args{rsaKey, mustCopy(rsaKey)}, true},
		{"ok ed25519Key", args{ed25519Key, mustCopy(ed25519Key)}, true},
		{"ok x25519Key", args{x25519Key, mustCopy(x25519Key)}, true},
		{"ok ecdsaKey pub", args{ecdsaKey.Public(), mustCopy(ecdsaKey).Public()}, true},
		{"ok rsaKey pub", args{rsaKey.Public(), mustCopy(rsaKey).Public()}, true},
		{"ok ed25519Key pub", args{ed25519Key.Public(), mustCopy(ed25519Key).Public()}, true},
		{"ok x25519Key pub", args{x25519Key.Public(), mustCopy(x25519Key).Public()}, true},
		{"ok []byte", args{[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}}, true},
		{"fail ecdsaKey", args{ecdsaKey, mustCopy(ecdsaKey).Public()}, false},
		{"fail rsaKey", args{rsaKey, mustCopy(rsaKey).Public()}, false},
		{"fail ed25519Key", args{ed25519Key, mustCopy(ed25519Key).Public()}, false},
		{"fail x25519Key", args{x25519Key, mustCopy(x25519Key).Public()}, false},
		{"fail ecdsaKey pub", args{ecdsaKey.Public(), mustCopy(ecdsaKey)}, false},
		{"fail rsaKey pub", args{rsaKey.Public(), mustCopy(rsaKey)}, false},
		{"fail ed25519Key pub", args{ed25519Key.Public(), mustCopy(ed25519Key)}, false},
		{"fail x25519Key pub", args{x25519Key.Public(), mustCopy(x25519Key)}, false},
		{"fail []byte", args{[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}}, false},
		{"fail int", args{1, 2}, false},
		{"fail string", args{"foo", "foo"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Equal(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}
