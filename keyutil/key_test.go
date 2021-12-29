package keyutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func setTeeReader(t *testing.T, w *bytes.Buffer) {
	t.Helper()
	reader := rand.Reader
	t.Cleanup(func() {
		rand.Reader = reader
	})
	rand.Reader = io.TeeReader(reader, w)
}

func TestPublicKey(t *testing.T) {
	ecdsaKey := must(generateECKey("P-256")).(*ecdsa.PrivateKey)
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
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	ecdsaKey, err := generateECKey("P-256")
	assert.FatalError(t, err)
	rand.Reader = buf

	tests := []struct {
		name    string
		want    interface{}
		wantErr bool
	}{
		{"ok", ecdsaKey, false},
		{"eof", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateDefaultKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDefaultKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateDefaultKey() = %T, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateDefaultKeyPair(t *testing.T) {
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	ecdsaKey := must(generateECKey("P-256")).(*ecdsa.PrivateKey)
	rand.Reader = buf

	tests := []struct {
		name    string
		want    interface{}
		want1   interface{}
		wantErr bool
	}{
		{"ok", ecdsaKey.Public(), ecdsaKey, false},
		{"eof", nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := GenerateDefaultKeyPair()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDefaultKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateDefaultKeyPair() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("GenerateDefaultKeyPair() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestGenerateKey(t *testing.T) {
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	p256Key, err := generateECKey("P-256")
	assert.FatalError(t, err)
	p384Key, err := generateECKey("P-384")
	assert.FatalError(t, err)
	p521Key, err := generateECKey("P-521")
	assert.FatalError(t, err)
	ed25519Key, err := generateOKPKey("Ed25519")
	assert.FatalError(t, err)
	octKey, err := generateOctKey(32)
	assert.FatalError(t, err)
	rand.Reader = buf

	type args struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PrivateKey
		wantErr bool
	}{
		{"P-256", args{"EC", "P-256", 0}, p256Key, false},
		{"P-384", args{"EC", "P-384", 0}, p384Key, false},
		{"P-521", args{"EC", "P-521", 0}, p521Key, false},
		{"Ed25519", args{"OKP", "Ed25519", 0}, ed25519Key, false},
		{"OCT", args{"oct", "", 32}, octKey, false},
		{"eof EC", args{"EC", "P-256", 0}, nil, true},
		{"eof RSA", args{"RSA", "", 1024}, nil, true},
		{"eof OKP", args{"OKP", "Ed25519", 0}, nil, true},
		{"eof oct", args{"oct", "", 32}, nil, true},
		{"unknown EC curve", args{"EC", "P-128", 0}, nil, true},
		{"unknown OKP curve", args{"OKP", "Edward", 0}, nil, true},
		{"unknown type", args{"FOO", "", 1024}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateKey(tt.args.kty, tt.args.crv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateKey() = %v, want %v", got, tt.want)
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
		{"RSA1024", args{"RSA", "", 1024}, reflect.TypeOf(&rsa.PrivateKey{}), false},
		{"RSA2048", args{"RSA", "", 2048}, reflect.TypeOf(&rsa.PrivateKey{}), false},
		{"fail", args{"RSA", "", 1}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	p256Key := must(generateECKey("P-256")).(*ecdsa.PrivateKey)
	p384Key := must(generateECKey("P-384")).(*ecdsa.PrivateKey)
	p521Key := must(generateECKey("P-521")).(*ecdsa.PrivateKey)
	ed25519Key := must(generateOKPKey("Ed25519")).(ed25519.PrivateKey)
	_, err := generateOctKey(32)
	assert.FatalError(t, err)
	rand.Reader = buf

	type args struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		want1   crypto.PrivateKey
		wantErr bool
	}{
		{"P-256", args{"EC", "P-256", 0}, p256Key.Public(), p256Key, false},
		{"P-384", args{"EC", "P-384", 0}, p384Key.Public(), p384Key, false},
		{"P-521", args{"EC", "P-521", 0}, p521Key.Public(), p521Key, false},
		{"Ed25519", args{"OKP", "Ed25519", 0}, ed25519Key.Public(), ed25519Key, false},
		{"OCT", args{"oct", "", 32}, nil, nil, true},
		{"eof", args{"EC", "P-256", 0}, nil, nil, true},
		{"unknown", args{"EC", "P-128", 0}, nil, nil, true},
		{"unknown", args{"FOO", "", 1024}, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := GenerateKeyPair(tt.args.kty, tt.args.crv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateKeyPair() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("GenerateKeyPair() got1 = %v, want %v", got1, tt.want1)
			}
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
		{"RSA1024", args{"RSA", "", 1024}, pubType, privType, false},
		{"RSA2048", args{"RSA", "", 2048}, pubType, privType, false},
		{"fail", args{"RSA", "", 1}, nil, nil, true},
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
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	ecdsaKey, err := generateECKey("P-256")
	assert.FatalError(t, err)
	rand.Reader = buf

	tests := []struct {
		name    string
		want    interface{}
		wantErr bool
	}{
		{"ok", ecdsaKey, false},
		{"eof", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateDefaultSigner()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDefaultSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateDefaultSigner() = %T, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateSigner(t *testing.T) {
	buf := new(bytes.Buffer)
	setTeeReader(t, buf)
	p256Key := must(generateECKey("P-256")).(*ecdsa.PrivateKey)
	p384Key := must(generateECKey("P-384")).(*ecdsa.PrivateKey)
	p521Key := must(generateECKey("P-521")).(*ecdsa.PrivateKey)
	ed25519Key := must(generateOKPKey("Ed25519")).(ed25519.PrivateKey)
	_, err := generateOctKey(32)
	assert.FatalError(t, err)
	rand.Reader = buf

	type args struct {
		kty  string
		crv  string
		size int
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"P-256", args{"EC", "P-256", 0}, p256Key, false},
		{"P-384", args{"EC", "P-384", 0}, p384Key, false},
		{"P-521", args{"EC", "P-521", 0}, p521Key, false},
		{"Ed25519", args{"OKP", "Ed25519", 0}, ed25519Key, false},
		{"OCT", args{"oct", "", 32}, nil, true},
		{"eof", args{"EC", "P-256", 0}, nil, true},
		{"unknown", args{"EC", "P-128", 0}, nil, true},
		{"unknown", args{"FOO", "", 1024}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateSigner(tt.args.kty, tt.args.crv, tt.args.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateSigner() = %v, want %v", got, tt.want)
			}
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
