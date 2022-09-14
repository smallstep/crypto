package pemutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"reflect"
	"testing"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

func TestParseCosignPrivateKey(t *testing.T) {
	b, err := os.ReadFile("testdata/cosign.enc.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("error decoding testdata/cosign.enc.pem")
	}

	var env cosignEnvelope
	if err := json.Unmarshal(block.Bytes, &env); err != nil {
		t.Fatal(err)
	}
	marshalEnv := func(in cosignEnvelope) []byte {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	want := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X: big.NewInt(0).SetBytes([]byte{
				0xdb, 0xa8, 0x69, 0x99, 0xc1, 0xda, 0xd8, 0x26,
				0x1a, 0xcf, 0xb9, 0x60, 0x4d, 0x62, 0x8b, 0x04,
				0xd9, 0x52, 0xbf, 0x61, 0x32, 0x3f, 0x14, 0xa2,
				0x2c, 0x61, 0xbc, 0xcb, 0xd5, 0xe4, 0xd9, 0x63,
			}),
			Y: big.NewInt(0).SetBytes([]byte{
				0x97, 0xab, 0x65, 0xa5, 0xd6, 0x76, 0x8f, 0xbe,
				0xb5, 0xb9, 0xe5, 0x9d, 0x5f, 0x93, 0xe5, 0xde,
				0x07, 0x58, 0x5e, 0xa6, 0x3a, 0x32, 0x26, 0x71,
				0xba, 0x06, 0x3f, 0x0c, 0xd6, 0x5e, 0x97, 0x2a,
			}),
		},
		D: big.NewInt(0).SetBytes([]byte{
			0x4c, 0x96, 0x4f, 0x6b, 0x65, 0x3b, 0x61, 0x1e,
			0xe1, 0x84, 0x4b, 0xa2, 0xf7, 0x5a, 0x59, 0xf2,
			0xab, 0x56, 0xf5, 0xdb, 0x6a, 0x96, 0x54, 0x6f,
			0xf0, 0xd7, 0x51, 0x99, 0x0f, 0x0b, 0xa5, 0x38,
		}),
	}

	type args struct {
		data     []byte
		password []byte
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PrivateKey
		wantErr bool
	}{
		{"ok", args{block.Bytes, []byte("mypassword")}, want, false},
		{"fail password", args{block.Bytes, []byte("password")}, nil, true},
		{"fail unmarshal", args{block.Bytes[1:], []byte("mypassword")}, nil, true},
		{"fail kdf", args{func() []byte {
			key := env
			key.KDF.Name = "bcrypt"
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
		{"fail cipher", args{func() []byte {
			key := env
			key.Cipher.Name = "nacl/box"
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
		{"fail nonce too large", args{func() []byte {
			key := env
			key.Cipher.Nonce = append(key.Cipher.Nonce, '0')
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
		{"fail nonce too short", args{func() []byte {
			key := env
			key.Cipher.Nonce = key.Cipher.Nonce[:23]
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
		{"fail kdf.N", args{func() []byte {
			key := env
			key.KDF.Params.N++
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
		{"fail kdf.R", args{func() []byte {
			key := env
			key.KDF.Params.R++
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
		{"fail kdf.P", args{func() []byte {
			key := env
			key.KDF.Params.P++
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
		{"fail kdf.Salt", args{func() []byte {
			key := env
			key.KDF.Salt[10]++
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
		{"fail ciphertext", args{func() []byte {
			key := env
			key.Ciphertext[10]++
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
		{"fail parsePKCS8PrivateKey", args{func() []byte {
			var n [24]byte
			var k [32]byte
			key := env
			b, err := scrypt.Key([]byte("mypassword"), key.KDF.Salt,
				key.KDF.Params.N, key.KDF.Params.R, key.KDF.Params.P, 32)
			if err != nil {
				t.Fatal(err)
			}
			copy(n[:], key.Cipher.Nonce)
			copy(k[:], b)
			key.Ciphertext = secretbox.Seal(nil, []byte("not a key"), &n, &k)
			return marshalEnv(key)
		}(), []byte("mypassword")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCosignPrivateKey(tt.args.data, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCosignPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseCosignPrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseCosignPrivateKey_equal(t *testing.T) {
	parsePem := func(fn string) []byte {
		b, err := os.ReadFile(fn)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			t.Fatalf("error decoding %s", fn)
		}
		return block.Bytes
	}

	key, err := ParseCosignPrivateKey(parsePem("testdata/cosign.enc.pem"), []byte("mypassword"))
	if err != nil {
		t.Errorf("ParseCosignPrivateKey() error = %v", err)
		return
	}

	priv, err := x509.ParsePKCS8PrivateKey(parsePem("testdata/cosign.pem"))
	if err != nil {
		t.Errorf("ParsePKCS8PrivateKey() error = %v", err)
		return
	}

	if !reflect.DeepEqual(priv, key) {
		t.Errorf("Private keys do not match() = %v, want %v", priv, key)
	}

	pub, err := x509.ParsePKIXPublicKey(parsePem("testdata/cosign.pub.pem"))
	if err != nil {
		t.Errorf("ParsePKIXPublicKey() error = %v", err)
		return
	}

	if !reflect.DeepEqual(pub, key.(crypto.Signer).Public()) {
		t.Errorf("Public keys do not match() = %v, want %v", pub, key.(crypto.Signer).Public())
	}
}

func TestParseCosignPrivateKey_IncorrectPasswordError(t *testing.T) {
	b, err := os.ReadFile("testdata/cosign.enc.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("error decoding testdata/cosign.enc.pem")
	}

	_, err = ParseCosignPrivateKey(block.Bytes, []byte("mypassword"))
	if err != nil {
		t.Errorf("ParseCosignPrivateKey() error = %v", err)
	}

	_, err = ParseCosignPrivateKey(block.Bytes, []byte("foobar"))
	if !errors.Is(err, x509.IncorrectPasswordError) {
		t.Errorf("ParseCosignPrivateKey() error = %v, wantErr = %v", err, x509.IncorrectPasswordError)
	}
}
