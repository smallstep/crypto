package pemutil

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptPKCS8(t *testing.T) {
	t.Parallel()
	password := []byte("mypassword")
	for fn, td := range files {
		// skip encrypted and public keys
		if td.encrypted || td.typ == rsaPublicKey || td.typ == ecdsaPublicKey || td.typ == ed25519PublicKey {
			continue
		}
		// skip x25519 keys
		if td.typ == x25519PublicKey || td.typ == x25519PrivateKey {
			continue
		}

		t.Run(fn, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(fn)
			require.NoError(t, err)

			key1, err := Parse(data)
			if err != nil {
				t.Errorf("failed to parse %s: %v", fn, err)
				return
			}

			data, err = x509.MarshalPKCS8PrivateKey(key1)
			if err != nil {
				t.Errorf("failed to marshal private key for %s: %v", fn, err)
				return
			}

			for _, alg := range rfc1423Algos {
				encBlock, err := EncryptPKCS8PrivateKey(rand.Reader, data, password, alg.cipher)
				if err != nil {
					t.Errorf("failed to decrypt %s with %s: %v", fn, alg.name, err)
					continue
				}
				assert.Equal(t, "ENCRYPTED PRIVATE KEY", encBlock.Type)
				assert.NotNil(t, encBlock.Bytes)
				assert.Nil(t, encBlock.Headers)

				data, err = DecryptPKCS8PrivateKey(encBlock.Bytes, password)
				if err != nil {
					t.Errorf("failed to decrypt %s with %s: %v", fn, alg.name, err)
					continue
				}

				key2, err := x509.ParsePKCS8PrivateKey(data)
				if err != nil {
					t.Errorf("failed to parse PKCS#8 key %s: %v", fn, err)
					continue
				}

				assert.Equal(t, key1, key2)
			}
		})
	}
}

func TestSerialize_PKCS8(t *testing.T) {
	mustPKIX := func(pub interface{}) *pem.Block {
		b, err := x509.MarshalPKIXPublicKey(pub)
		require.NoError(t, err)
		return &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		}
	}
	mustPKCS8 := func(priv interface{}) *pem.Block {
		b, err := x509.MarshalPKCS8PrivateKey(priv)
		require.NoError(t, err)
		return &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		}
	}

	rsaKey, err := Read("testdata/openssl.rsa2048.pem")
	require.NoError(t, err)
	ecdsaKey, err := Read("testdata/openssl.p256.pem")
	require.NoError(t, err)
	edKey, err := Read("testdata/pkcs8/openssl.ed25519.pem")
	require.NoError(t, err)

	rsaKeyPub := rsaKey.(*rsa.PrivateKey).Public()
	ecdsaKeyPub := ecdsaKey.(*ecdsa.PrivateKey).Public()
	edKeyPub := edKey.(ed25519.PrivateKey).Public()

	type args struct {
		pub interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    *pem.Block
		wantErr bool
	}{
		{"rsa", args{rsaKey}, mustPKCS8(rsaKey), false},
		{"rsa pub", args{rsaKeyPub}, mustPKIX(rsaKeyPub), false},
		{"ecdsa", args{ecdsaKey}, mustPKCS8(ecdsaKey), false},
		{"ecdsa pub", args{ecdsaKeyPub}, mustPKIX(ecdsaKeyPub), false},
		{"ed25519", args{edKey}, mustPKCS8(edKey), false},
		{"ed25519 pub", args{edKeyPub}, mustPKIX(edKeyPub), false},
		{"fail", args{[]byte("fooobar")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// got, err := x509.MarshalPKIXPublicKey(tt.args.pub)
			got, err := Serialize(tt.args.pub, WithPKCS8(true))
			if (err != nil) != tt.wantErr {
				t.Errorf("Serialize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Serialize() = \n got %v, \nwant %v", got, tt.want)
			}
		})
	}
}

func TestDecryptPKCS8PrivateKey(t *testing.T) {
	password := []byte("mypassword")

	for name, td := range files {
		// skip non-encrypted and non pkcs8 keys
		if !td.encrypted || !strings.HasPrefix(name, "testdata/pkcs8/") {
			continue
		}

		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(name)
			if err != nil {
				t.Errorf("os.ReadFile() error = %v", err)
				return
			}
			block, _ := pem.Decode(data)
			if block == nil {
				t.Errorf("pem.Decode() failed, block = %v", block)
				return
			}
			data, err = DecryptPKCS8PrivateKey(block.Bytes, password)
			if err != nil {
				t.Errorf("DecryptPKCS8PrivateKey() error = %v", err)
				return
			}
			// Invalid password
			_, err = DecryptPKCS8PrivateKey(block.Bytes, []byte("foobar"))
			if !errors.Is(err, x509.IncorrectPasswordError) {
				t.Errorf("DecryptPKCS8PrivateKey() error=%v, wantErr=%v", err, x509.IncorrectPasswordError)
			}
			_, err = x509.ParsePKCS8PrivateKey(data)
			if err != nil {
				t.Errorf("x509.ParsePKCS8PrivateKey() error = %v", err)
			}
		})
	}
}

func TestDecryptPKCS8PrivateKey_ciphers(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	password := []byte("mypassword")
	for _, alg := range rfc1423Algos {
		t.Run(alg.name, func(t *testing.T) {
			encData, err := EncryptPKCS8PrivateKey(rand.Reader, data, password, alg.cipher)
			if err != nil {
				t.Errorf("EncryptPKCS8PrivateKey() error = %v", err)
				return
			}
			decData, err := DecryptPKCS8PrivateKey(encData.Bytes, password)
			if err != nil {
				t.Errorf("DecryptPKCS8PrivateKey() error = %v", err)
				return
			}

			// Invalid password.
			//
			// Because of the only way to check if the password is correct or
			// not is checking the padding data, it's possible and probably
			// enough to get a padding length of 1, with the data 01. If this
			// happens the DecryptPKCS8PrivateKey will not return an error, but
			// it will return bad data. We will check before if the data is
			// correct before erroring.
			badData, err := DecryptPKCS8PrivateKey(encData.Bytes, []byte("foobar"))
			if !errors.Is(err, x509.IncorrectPasswordError) {
				if _, err := x509.ParsePKCS8PrivateKey(badData); err == nil {
					t.Errorf("DecryptPKCS8PrivateKey() error=%v, wantErr=%v", err, x509.IncorrectPasswordError)
				}
			}

			// Check with original key
			key, err := x509.ParsePKCS8PrivateKey(decData)
			if err != nil {
				t.Errorf("x509.ParsePKCS8PrivateKey() error = %v", err)
			}

			if !reflect.DeepEqual(key, priv) {
				t.Errorf("DecryptPKCS8PrivateKey() got = %v, want = %v", key, priv)
			}
		})

	}
}
