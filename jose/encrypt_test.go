package jose

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"io"
	"reflect"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
	"github.com/smallstep/assert"
	"go.step.sm/crypto/randutil"
)

var testPassword = []byte("Supercalifragilisticexpialidocious")

// mustTeeReader returns a buffer that can be used to capture reads from
// rand.Reader and replay them if we set `rand.Reader` to that buffer.
// mustTeeReader resets rand.Reader on cleanup.
func mustTeeReader(t *testing.T) *bytes.Buffer {
	t.Helper()
	reader := rand.Reader
	t.Cleanup(func() {
		rand.Reader = reader
		jose.RandReader = reader
	})
	buf := new(bytes.Buffer)
	rand.Reader = io.TeeReader(reader, buf)
	jose.RandReader = rand.Reader
	return buf
}

func mustGenerateJWK(t *testing.T, kty, crv, alg, use, kid string, size int) *JSONWebKey {
	t.Helper()
	jwk, err := GenerateJWK(kty, crv, alg, use, kid, size)
	if err != nil {
		t.Fatal(err)
	}
	return jwk
}

func mustEncryptJWK(t *testing.T, jwk *JSONWebKey, passphrase []byte) *JSONWebEncryption {
	t.Helper()
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return mustEncryptData(t, data, passphrase)
}

func mustEncryptData(t *testing.T, data, passphrase []byte) *JSONWebEncryption {
	t.Helper()

	salt, err := randutil.Salt(PBKDF2SaltSize)
	if err != nil {
		t.Fatal(err)
	}

	recipient := Recipient{
		Algorithm:  PBES2_HS256_A128KW,
		Key:        passphrase,
		PBES2Count: PBKDF2Iterations,
		PBES2Salt:  salt,
	}

	opts := new(EncrypterOptions)
	if bytes.HasPrefix(data, []byte("{")) {
		opts.WithContentType(ContentType("jwk+json"))
	}
	encrypter, err := NewEncrypter(DefaultEncAlgorithm, recipient, opts)
	if err != nil {
		t.Fatal(err)
	}

	jwe, err := encrypter.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}

	return jwe
}

func fixJWK(jwk *JSONWebKey) *JSONWebKey {
	jwk.Certificates = []*x509.Certificate{}
	jwk.CertificatesURL = nil
	jwk.CertificateThumbprintSHA1 = []uint8{}
	jwk.CertificateThumbprintSHA256 = []uint8{}
	return jwk
}

// rsaEqual reports whether priv and x have equivalent values. It ignores
// Precomputed values.
func rsaEqual(priv *rsa.PrivateKey, x crypto.PrivateKey) bool {
	xx, ok := x.(*rsa.PrivateKey)
	if !ok {
		return false
	}
	if !(priv.PublicKey.N.Cmp(xx.N) == 0 && priv.PublicKey.E == xx.E) || priv.D.Cmp(xx.D) != 0 {
		return false
	}
	if len(priv.Primes) != len(xx.Primes) {
		return false
	}
	for i := range priv.Primes {
		if priv.Primes[i].Cmp(xx.Primes[i]) != 0 {
			return false
		}
	}
	return true
}

func TestEncrypt(t *testing.T) {
	jwk := fixJWK(mustGenerateJWK(t, "EC", "P-256", "ES256", "", "", 0))
	data, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		data []byte
		opts []Option
	}
	tests := []struct {
		name    string
		args    args
		wantFn  func(t *testing.T) *JSONWebEncryption
		wantErr bool
	}{
		{"ok", args{data, []Option{WithPassword([]byte("password")), WithContentType("jwk+json")}},
			func(t *testing.T) *JSONWebEncryption {
				reader := mustTeeReader(t)
				jwe := mustEncryptJWK(t, jwk, []byte("password"))
				rand.Reader = reader
				jose.RandReader = reader
				return jwe
			}, false},
		{"ok WithPasswordPrompter", args{data, []Option{
			WithContentType("jwk+json"),
			WithPasswordPrompter("Enter the password", func(s string) ([]byte, error) {
				return []byte("password"), nil
			})}},
			func(t *testing.T) *JSONWebEncryption {
				reader := mustTeeReader(t)
				jwe := mustEncryptJWK(t, jwk, []byte("password"))
				rand.Reader = reader
				jose.RandReader = reader
				return jwe
			}, false},
		{"ok with PromptPassword", args{data, []Option{WithContentType("jwk+json")}},
			func(t *testing.T) *JSONWebEncryption {
				tmp := PromptPassword
				t.Cleanup(func() { PromptPassword = tmp })
				PromptPassword = func(s string) ([]byte, error) {
					return []byte("password"), nil
				}
				reader := mustTeeReader(t)
				jwe := mustEncryptJWK(t, jwk, []byte("password"))
				rand.Reader = reader
				jose.RandReader = reader
				return jwe
			}, false},
		{"fail apply", args{data, []Option{WithPasswordFile("testdata/missing.txt")}},
			func(t *testing.T) *JSONWebEncryption {
				return nil
			}, true},
		{"fail WithPasswordPrompter", args{data, []Option{
			WithContentType("jwk+json"),
			WithPasswordPrompter("Enter the password", func(s string) ([]byte, error) {
				return nil, errors.New("test error")
			})}},
			func(t *testing.T) *JSONWebEncryption {
				return nil
			}, true},
		{"fail with PromptPassword", args{data, []Option{WithContentType("jwk+json")}},
			func(t *testing.T) *JSONWebEncryption {
				tmp := PromptPassword
				t.Cleanup(func() { PromptPassword = tmp })
				PromptPassword = func(s string) ([]byte, error) {
					return nil, errors.New("test error")
				}
				return nil
			}, true},
		{"fail no passowrd", args{data, nil},
			func(t *testing.T) *JSONWebEncryption {
				return nil
			}, true},
		{"fail encrypt", args{data, []Option{WithPassword([]byte("password"))}},
			func(t *testing.T) *JSONWebEncryption {
				reader := mustTeeReader(t)
				_, _ = randutil.Salt(PBKDF2SaltSize)
				rand.Reader = reader
				jose.RandReader = reader
				return nil
			}, true},
		{"fail salt", args{data, []Option{WithPassword([]byte("password"))}},
			func(t *testing.T) *JSONWebEncryption {
				reader := mustTeeReader(t)
				rand.Reader = reader
				jose.RandReader = reader
				return nil
			}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.wantFn(t)
			got, err := Encrypt(tt.args.data, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Encrypt() = %v, want %v", got, want)
			}
		})
	}
}

func TestEncryptJWK(t *testing.T) {
	jwk := fixJWK(mustGenerateJWK(t, "EC", "P-256", "ES256", "", "", 0))

	type args struct {
		jwk        *JSONWebKey
		passphrase []byte
	}
	tests := []struct {
		name    string
		args    args
		wantFn  func(t *testing.T) *JSONWebEncryption
		wantErr bool
	}{
		{"ok", args{jwk, []byte("planned password")}, func(t *testing.T) *JSONWebEncryption {
			reader := mustTeeReader(t)
			jwe := mustEncryptJWK(t, jwk, []byte("planned password"))
			rand.Reader = reader
			jose.RandReader = reader
			return jwe
		}, false},
		{"fail marshal", args{&JSONWebKey{Key: "a string"}, []byte("planned password")}, func(t *testing.T) *JSONWebEncryption {
			return nil
		}, true},
		{"fail encrypt", args{jwk, []byte("planned password")}, func(t *testing.T) *JSONWebEncryption {
			reader := mustTeeReader(t)
			_, _ = randutil.Salt(PBKDF2SaltSize)
			rand.Reader = reader
			jose.RandReader = reader
			return nil
		}, true},
		{"fail salt", args{jwk, []byte("planned password")}, func(t *testing.T) *JSONWebEncryption {
			reader := mustTeeReader(t)
			rand.Reader = reader
			jose.RandReader = reader
			return nil
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.wantFn(t)
			got, err := EncryptJWK(tt.args.jwk, tt.args.passphrase)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptJWK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("EncryptJWK() = %v, want %v", got, want)
			}
		})
	}
}

func TestEncryptDecryptJWK(t *testing.T) {
	t.Parallel()
	ecKey := fixJWK(mustGenerateJWK(t, "EC", "P-256", "ES256", "enc", "", 0))
	rsaKey := fixJWK(mustGenerateJWK(t, "RSA", "", "RS256", "sig", "", 2048))
	rsaPSSKey := fixJWK(mustGenerateJWK(t, "RSA", "", "PS256", "enc", "", 2048))
	edKey := fixJWK(mustGenerateJWK(t, "OKP", "Ed25519", "EdDSA", "sig", "", 0))
	octKey := fixJWK(mustGenerateJWK(t, "oct", "", "HS256", "sig", "", 64))

	type args struct {
		jwk        JSONWebKey
		passphrase []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok EC", args{*ecKey, testPassword}, false},
		{"ok EC pub", args{ecKey.Public(), testPassword}, false},
		{"ok RSA", args{*rsaKey, testPassword}, false},
		{"ok RSA pub", args{rsaKey.Public(), testPassword}, false},
		{"ok RSA-PSS", args{*rsaPSSKey, testPassword}, false},
		{"ok RSA-PSS pub", args{rsaPSSKey.Public(), testPassword}, false},
		{"ok Ed25519", args{*edKey, testPassword}, false},
		{"ok Ed25519 pub", args{edKey.Public(), testPassword}, false},
		{"ok oct", args{*octKey, testPassword}, false},
	}
	for _, tc := range tests {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := EncryptJWK(&tt.args.jwk, tt.args.passphrase)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptJWK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			s, err := got.CompactSerialize()
			if err != nil {
				t.Errorf("EncrypCompactSerializetJWK() error = %v", err)
				return
			}

			data, err := Decrypt([]byte(s), WithPassword(tt.args.passphrase))
			if err != nil {
				t.Errorf("Decrypt() error = %v", err)
				return
			}

			var jwk JSONWebKey
			if err := json.Unmarshal(data, &jwk); err != nil {
				t.Errorf("json.Unmarshal() error = %v", err)
				return
			}

			// Make the rsa keys equal if they are
			if k, ok := tt.args.jwk.Key.(*rsa.PrivateKey); ok {
				if !rsaEqual(k, jwk.Key) {
					t.Errorf("Decrypt() got = %v, want %v", jwk.Key, tt.args.jwk.Key)
					return
				}
				jwk.Key = k
			}

			if !reflect.DeepEqual(jwk, tt.args.jwk) {
				t.Errorf("Decrypt() got = %v, want %v", jwk, tt.args.jwk)
			}
		})
	}
}

func TestDecrypt(t *testing.T) {
	data := []byte("the-plain-data")
	jwe := mustEncryptData(t, data, testPassword)
	s, err := jwe.CompactSerialize()
	assert.FatalError(t, err)
	encryptedData := []byte(s)

	// Create wrong encrypted data
	m := make(map[string]interface{})
	if err := json.Unmarshal([]byte(jwe.FullSerialize()), &m); err != nil {
		t.Fatal(err)
	}
	m["iv"] = "bad-iv"
	badEncryptedData, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		data             []byte
		opts             []Option
		passwordPrompter PasswordPrompter
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok not encrypted", args{[]byte("foobar"), nil, nil}, []byte("foobar"), false},
		{"ok WithPassword", args{encryptedData, []Option{WithPassword(testPassword)}, nil}, data, false},
		{"ok WithPasswordFile", args{encryptedData, []Option{WithPasswordFile("testdata/passphrase.txt")}, nil}, data, false},
		{"ok WithPasswordPrompter", args{encryptedData, []Option{WithPasswordPrompter("What's the password?", func(s string) ([]byte, error) {
			return testPassword, nil
		})}, nil}, data, false},
		{"ok PasswordPrompter", args{encryptedData, []Option{}, func(s string) ([]byte, error) {
			return testPassword, nil
		}}, data, false},
		{"ok WithFilename and PasswordPrompter", args{encryptedData, []Option{WithFilename("test.jwk")}, func(s string) ([]byte, error) {
			return testPassword, nil
		}}, data, false},
		{"fail bad data", args{badEncryptedData, []Option{WithPassword(testPassword)}, nil}, nil, true},
		{"fail WithPassword", args{encryptedData, []Option{WithPassword([]byte("bad-password"))}, nil}, nil, true},
		{"fail WithPasswordFile", args{encryptedData, []Option{WithPasswordFile("testdata/oct.txt")}, nil}, nil, true},
		{"fail WithPasswordPrompter", args{encryptedData, []Option{WithPasswordPrompter("What's the password?", func(s string) ([]byte, error) {
			return []byte("bad-password"), nil
		})}, nil}, nil, true},
		{"fail PasswordPrompter", args{encryptedData, []Option{}, func(s string) ([]byte, error) {
			return []byte("bad-password"), nil
		}}, nil, true},
		{"fail apply WithPassword", args{encryptedData, []Option{WithPasswordFile("testdata/missing.txt")}, nil}, nil, true},
		{"fail apply WithPasswordPrompter", args{encryptedData, []Option{WithPasswordPrompter("What's the password?", func(s string) ([]byte, error) {
			return nil, errors.New("unexpected error")
		})}, nil}, nil, true},
		{"fail PasswordPrompter", args{encryptedData, []Option{}, func(s string) ([]byte, error) {
			return nil, errors.New("unexpected error")
		}}, nil, true},
		{"fail WithFilename and PasswordPrompter", args{encryptedData, []Option{WithFilename("test.jwk")}, func(s string) ([]byte, error) {
			return nil, errors.New("unexpected error")
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "okGlobalPasswordPrompter" {
				t.Log("foo")
			}
			tmp := PromptPassword
			t.Cleanup(func() { PromptPassword = tmp })
			PromptPassword = tt.args.passwordPrompter

			got, err := Decrypt(tt.args.data, tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecrypt_highP2C(t *testing.T) {
	data := []byte(`{
	"protected":"eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMjU2R0NNIiwicDJjIjoyMDAwMDAwMDAwMCwicDJzIjoiM3V0aFJZdHBTY09UMjR4Q3cwbTlfQSJ9",
	"encrypted_key":"Lqn-BuAIole2T5ubPIPXl1QYj_48JqyeEfbOLq0EkyAX96irRPHA4g",
	"iv":"eGaXW9_umwZvLCSP",
	"ciphertext":"enFrF3NyvTN_a6Y4",
	"tag":"VQFg97XqcRo61punp7Z3ow"
}`)

	timer := time.AfterFunc(time.Second, func() {
		t.Fatal("Decrypt() took to much time")
	})

	_, err := Decrypt(data, WithPassword([]byte("password")))
	assert.Error(t, err)
	if !timer.Stop() {
		<-timer.C
	}
}
