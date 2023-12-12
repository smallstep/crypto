package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"reflect"
	"testing"

	jose "github.com/go-jose/go-jose/v3"
	"github.com/smallstep/assert"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/x25519"
)

func TestThumbprint(t *testing.T) {
	parse := func(filename string) *JSONWebKey {
		jwk, err := ReadKey(filename)
		if err != nil {
			t.Fatal(err)
		}
		return jwk
	}

	x25519Key := x25519.PrivateKey{
		0xe9, 0xc5, 0xce, 0xce, 0xf8, 0x2b, 0xd5, 0xee,
		0x98, 0x72, 0xea, 0xd4, 0xc9, 0x66, 0xab, 0x3d,
		0xc3, 0x19, 0xe5, 0xbd, 0xce, 0xe3, 0xcb, 0x03,
		0x6c, 0xdc, 0xaf, 0x04, 0x61, 0xe1, 0xe3, 0x5d,
	}

	jwk := parse("testdata/p256.priv.json")
	s, ok := jwk.Key.(crypto.Signer)
	if !ok {
		t.Fatalf("type %T does not implement crypto.Signer", jwk.Key)
	}
	opaqueKey := &JSONWebKey{
		Key: NewOpaqueSigner(s),
	}

	type args struct {
		jwk *JSONWebKey
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ec", args{parse("testdata/p256.priv.json")}, "V93A-Yh7Bhw1W2E0igFciviJzX4PXPswoVgriehm9Co", false},
		{"ec pub", args{parse("testdata/p256.pub.json")}, "V93A-Yh7Bhw1W2E0igFciviJzX4PXPswoVgriehm9Co", false},
		{"rsa", args{parse("testdata/rsa.priv.json")}, "CIsktcixZ5GyfkoWFyEV0tp5foASmBV4D-W7clYrCu8", false},
		{"rsa pub", args{parse("testdata/rsa.pub.json")}, "CIsktcixZ5GyfkoWFyEV0tp5foASmBV4D-W7clYrCu8", false},
		{"okp", args{parse("testdata/okp.priv.json")}, "qiCJG7r2L80rmWRrZMPfpanQHmZRcncOG7A7MBWn9qM", false},
		{"okp pub", args{parse("testdata/okp.pub.json")}, "qiCJG7r2L80rmWRrZMPfpanQHmZRcncOG7A7MBWn9qM", false},
		{"x25519", args{&JSONWebKey{Key: x25519Key}}, "ir3T3GeoaZWjfhX-K_7c6E01N4mwLPehV_FyBAk28Vk", false},
		{"x25519 pub", args{&JSONWebKey{Key: x25519Key.Public()}}, "ir3T3GeoaZWjfhX-K_7c6E01N4mwLPehV_FyBAk28Vk", false},
		{"opaque", args{opaqueKey}, "V93A-Yh7Bhw1W2E0igFciviJzX4PXPswoVgriehm9Co", false},
		{"fail oct", args{parse("testdata/oct.json")}, "", true},
		{"fail x25519", args{&JSONWebKey{Key: x25519.PrivateKey("foobar")}}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Thumbprint(tt.args.jwk)
			if (err != nil) != tt.wantErr {
				t.Errorf("Thumbprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Thumbprint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateJWK(t *testing.T) {
	t.Parallel()
	tests := []struct {
		kty, crv, alg, use, kid string
		size                    int
		expectedAlg             string
		expectedSize            int
		expectedType            interface{}
		ok                      bool
	}{
		{"EC", "", "", "", "", 0, "ES256", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "", "sig", "", 0, "ES256", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-384", "", "sig", "a-kid", 0, "ES384", 384, &ecdsa.PrivateKey{}, true},
		{"EC", "P-521", "ES521", "sig", "a-kid", 0, "ES521", 521, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "", "enc", "a-kid", 0, "ECDH-ES", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "ECDH-ES+A128KW", "enc", "a-kid", 0, "ECDH-ES+A128KW", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "ECDH-ES+A192KW", "enc", "a-kid", 0, "ECDH-ES+A192KW", 256, &ecdsa.PrivateKey{}, true},
		{"EC", "P-256", "ECDH-ES+A256KW", "enc", "a-kid", 0, "ECDH-ES+A256KW", 256, &ecdsa.PrivateKey{}, true},
		{"RSA", "", "", "", "", 0, "RS256", 2048, &rsa.PrivateKey{}, true},
		{"RSA", "", "", "", "", 4096, "RS256", 4096, &rsa.PrivateKey{}, true},
		{"RSA", "", "RS384", "sig", "", 2048, "RS384", 2048, &rsa.PrivateKey{}, true},
		{"RSA", "", "RS521", "sig", "a-kid", 2048, "RS521", 2048, &rsa.PrivateKey{}, true},
		{"RSA", "", "", "enc", "a-kid", 2048, "RSA-OAEP-256", 2048, &rsa.PrivateKey{}, true},
		{"RSA", "", "RSA-OAEP-256", "enc", "a-kid", 2048, "RSA-OAEP-256", 2048, &rsa.PrivateKey{}, true},
		{"RSA", "", "RSA1_5", "enc", "a-kid", 2048, "RSA1_5", 2048, &rsa.PrivateKey{}, true},
		{"RSA", "", "RSA-OAEP", "enc", "a-kid", 2048, "RSA-OAEP", 2048, &rsa.PrivateKey{}, true},
		{"OKP", "", "", "", "", 0, "EdDSA", 64, ed25519.PrivateKey{}, true},
		{"OKP", "", "", "", "sig", 0, "EdDSA", 64, ed25519.PrivateKey{}, true},
		{"OKP", "", "", "EdDSA", "sig", 0, "EdDSA", 64, ed25519.PrivateKey{}, true},
		{"oct", "", "", "", "", 0, "HS256", 32, []byte{}, true},
		{"oct", "", "", "sig", "", 0, "HS256", 32, []byte{}, true},
		{"oct", "", "HS384", "sig", "a-kid", 16, "HS384", 16, []byte{}, true},
		{"oct", "", "HS521", "sig", "a-kid", 64, "HS521", 64, []byte{}, true},
		{"oct", "", "", "enc", "a-kid", 64, "A256GCMKW", 64, []byte{}, true},
		{"oct", "", "dir", "enc", "a-kid", 0, "dir", 32, []byte{}, true},
		{"oct", "", "A128KW", "enc", "a-kid", 0, "A128KW", 32, []byte{}, true},
		{"oct", "", "A192KW", "enc", "a-kid", 0, "A192KW", 32, []byte{}, true},
		{"oct", "", "A256KW", "enc", "a-kid", 0, "A256KW", 32, []byte{}, true},
		{"oct", "", "A128GCMKW", "enc", "a-kid", 0, "A128GCMKW", 32, []byte{}, true},
		{"oct", "", "A192GCMKW", "enc", "a-kid", 0, "A192GCMKW", 32, []byte{}, true},
		{"oct", "", "A256GCMKW", "enc", "a-kid", 0, "A256GCMKW", 32, []byte{}, true},
		{"fail", "", "", "", "", 0, "", 0, nil, false},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.kty, func(t *testing.T) {
			t.Parallel()
			jwk, err := GenerateJWK(tc.kty, tc.crv, tc.alg, tc.use, tc.kid, tc.size)
			if !tc.ok {
				assert.Error(t, err)
				assert.Nil(t, jwk)
				return
			}
			assert.NoError(t, err)
			if tc.kid != "" {
				assert.Equals(t, tc.kid, jwk.KeyID)
			}
			assert.Equals(t, tc.expectedAlg, jwk.Algorithm)
			assert.Type(t, tc.expectedType, jwk.Key)

			switch key := jwk.Key.(type) {
			case *ecdsa.PrivateKey:
				switch tc.expectedSize {
				case 256:
					assert.Equals(t, elliptic.P256(), key.Curve)
				case 384:
					assert.Equals(t, elliptic.P384(), key.Curve)
				case 521:
					assert.Equals(t, elliptic.P521(), key.Curve)
				default:
					t.Errorf("unexpected size %d", tc.expectedSize)
				}
			case *rsa.PrivateKey:
				assert.Equals(t, tc.expectedSize, key.N.BitLen())
			case ed25519.PrivateKey:
				assert.Equals(t, tc.expectedSize, len(key))
			case []byte:
				assert.Equals(t, tc.expectedSize, len(key))
			default:
				t.Errorf("unexpected key type %T", key)
			}
		})
	}
}

func TestKeyUsageForCert(t *testing.T) {
	tests := []struct {
		Cert      *x509.Certificate
		ExpectUse string
		ExpectErr error
	}{
		{
			Cert: &x509.Certificate{
				KeyUsage: x509.KeyUsageDigitalSignature,
			},
			ExpectUse: jwksUsageSig,
		},
		{
			Cert: &x509.Certificate{
				KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
			},
			ExpectUse: jwksUsageSig,
		},
		{
			Cert: &x509.Certificate{
				KeyUsage: x509.KeyUsageDataEncipherment | x509.KeyUsageKeyAgreement,
			},
			ExpectUse: jwksUsageEnc,
		},
		{
			Cert: &x509.Certificate{
				KeyUsage: x509.KeyUsageDataEncipherment,
			},
			ExpectUse: jwksUsageEnc,
		},
		{
			Cert:      &x509.Certificate{},
			ExpectErr: errNoCertKeyUsage,
		},
		{
			Cert: &x509.Certificate{
				KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
			},
			ExpectErr: errAmbiguousCertKeyUsage,
		},
	}

	for _, tt := range tests {
		use, err := keyUsageForCert(tt.Cert)
		if tt.ExpectErr != nil {
			assert.Equals(t, tt.ExpectErr, err)
		} else {
			assert.Equals(t, tt.ExpectUse, use)
		}
	}
}

func TestGenerateJWKFromPEM(t *testing.T) {
	t.Parallel()
	mustKey := func(filename string) interface{} {
		key, err := pemutil.Read(filename)
		assert.FatalError(t, err)
		return key
	}
	mustCert := func(filename string) *x509.Certificate {
		cert, err := pemutil.ReadCertificate(filename)
		assert.FatalError(t, err)
		return cert
	}
	type args struct {
		filename string
		subtle   bool
	}
	tests := []struct {
		name    string
		args    args
		want    *JSONWebKey
		wantErr bool
	}{
		{"p256", args{"../pemutil/testdata/openssl.p256.pem", false}, &JSONWebKey{
			Key:       mustKey("../pemutil/testdata/openssl.p256.pem"),
			Algorithm: ES256,
		}, false},
		{"p384", args{"../pemutil/testdata/openssl.p384.pem", false}, &JSONWebKey{
			Key:       mustKey("../pemutil/testdata/openssl.p384.pem"),
			Algorithm: ES384,
		}, false},
		{"p521", args{"../pemutil/testdata/openssl.p521.pem", false}, &JSONWebKey{
			Key:       mustKey("../pemutil/testdata/openssl.p521.pem"),
			Algorithm: ES512,
		}, false},
		{"ed25519", args{"../pemutil/testdata/pkcs8/openssl.ed25519.pem", false}, &JSONWebKey{
			Key:       mustKey("../pemutil/testdata/pkcs8/openssl.ed25519.pem"),
			Algorithm: EdDSA,
		}, false},
		{"rsa", args{"../pemutil/testdata/openssl.rsa2048.pem", false}, &JSONWebKey{
			Key: mustKey("../pemutil/testdata/openssl.rsa2048.pem"),
		}, false},
		{"p256 pub", args{"../pemutil/testdata/openssl.p256.pub.pem", false}, &JSONWebKey{
			Key:       mustKey("../pemutil/testdata/openssl.p256.pub.pem"),
			Algorithm: ES256,
		}, false},
		{"p384 pub", args{"../pemutil/testdata/openssl.p384.pub.pem", false}, &JSONWebKey{
			Key:       mustKey("../pemutil/testdata/openssl.p384.pub.pem"),
			Algorithm: ES384,
		}, false},
		{"p521 pub", args{"../pemutil/testdata/openssl.p521.pub.pem", false}, &JSONWebKey{
			Key:       mustKey("../pemutil/testdata/openssl.p521.pub.pem"),
			Algorithm: ES512,
		}, false},
		{"ed25519 pub", args{"../pemutil/testdata/pkcs8/openssl.ed25519.pub.pem", false}, &JSONWebKey{
			Key:       mustKey("../pemutil/testdata/pkcs8/openssl.ed25519.pub.pem"),
			Algorithm: EdDSA,
		}, false},
		{"rsa pub", args{"../pemutil/testdata/openssl.rsa2048.pub.pem", false}, &JSONWebKey{
			Key: mustKey("../pemutil/testdata/openssl.rsa2048.pub.pem"),
		}, false},
		{"rsa cert", args{"testdata/rsa2048.crt", true}, &JSONWebKey{
			Key:          mustCert("testdata/rsa2048.crt").PublicKey,
			Certificates: []*x509.Certificate{mustCert("testdata/rsa2048.crt")},
		}, false},
		{"ed25519 cert", args{"../x509util/testdata/ed25519.crt", true}, &JSONWebKey{
			Key:          mustCert("../x509util/testdata/ed25519.crt").PublicKey,
			Certificates: []*x509.Certificate{mustCert("../x509util/testdata/ed25519.crt")},
			Algorithm:    EdDSA,
		}, false},
		{"p256 cert", args{"../x509util/testdata/google.crt", false}, &JSONWebKey{
			Key:          mustCert("../x509util/testdata/google.crt").PublicKey,
			Certificates: []*x509.Certificate{mustCert("../x509util/testdata/google.crt")},
			Algorithm:    ES256,
			Use:          "sig",
		}, false},
		{"fail missing", args{"testdata/missing.txt", false}, nil, true},
		{"fail no subtle", args{"testdata/rsa2048.crt", false}, nil, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := GenerateJWKFromPEM(tt.args.filename, tt.args.subtle)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateJWKFromPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateJWKFromPEM() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateJWKFromPEMSubtle(t *testing.T) {
	tests := []struct {
		Description string
		KeyUsage    x509.KeyUsage
		Subtle      bool
		ExpectErr   error
		ExpectSig   string
	}{
		{
			Description: "single key usage without subtle",
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExpectSig:   jwksUsageSig,
		},
		{
			Description: "single key usage with subtle",
			KeyUsage:    x509.KeyUsageDigitalSignature,
			Subtle:      true,
		},
		{
			Description: "multiple key usage without subtle",
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExpectErr:   errAmbiguousCertKeyUsage,
		},
		{
			Description: "multiple key usage with subtle",
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			Subtle:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Description, func(t *testing.T) {
			f, cleanup := tempFile(t)
			defer cleanup()

			err := pem.Encode(f, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: newCert(t, tt.KeyUsage),
			})
			assert.NoError(t, err)

			jwk, err := GenerateJWKFromPEM(f.Name(), tt.Subtle)
			if tt.ExpectErr != nil {
				assert.Equals(t, tt.ExpectErr, err)
				return
			}
			assert.NoError(t, err)
			assert.Equals(t, tt.ExpectSig, jwk.Use)
			assert.Equals(t, ES256, jwk.Algorithm)
			assert.Equals(t, 1, len(jwk.Certificates))
		})
	}
}

func newCert(t *testing.T, keyUsage x509.KeyUsage) []byte {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		KeyUsage:     keyUsage,
	}
	cert, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, key.Public(), key)
	assert.NoError(t, err)
	return cert
}

func tempFile(t *testing.T) (*os.File, func()) {
	f, err := os.CreateTemp("", "jose-generate-test")
	assert.NoError(t, err)
	return f, func() {
		f.Close()
		os.Remove(f.Name())
	}
}

type mockReader struct{}

func (mockReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = byte(i % 256)
	}
	return len(buf), nil
}

type eofReader struct{}

func (eofReader) Read(buf []byte) (int, error) {
	return 0, io.EOF
}

func TestGenerateDefaultKeyPair(t *testing.T) {
	rr := rand.Reader
	t.Cleanup(func() {
		rand.Reader = rr
		jose.RandReader = rr
	})

	rand.Reader = mockReader{}
	jose.RandReader = mockReader{}
	jwk := mustGenerateJWK(t, "EC", "P-256", "ES256", "sig", "", 0)
	jwe := mustEncryptJWK(t, jwk, []byte("planned password"))

	var err error
	if jwk.KeyID, err = Thumbprint(jwk); err != nil {
		t.Fatal(err)
	}
	jwkPub := jwk.Public()

	type args struct {
		passphrase []byte
		randReader io.Reader
	}
	tests := []struct {
		name           string
		args           args
		want           *JSONWebKey
		want1          *JSONWebEncryption
		want1Decrypted *JSONWebKey
		wantErr        bool
	}{
		{"ok", args{[]byte("planned password"), mockReader{}}, &jwkPub, jwe, jwk, false},
		{"failEmptyPassword", args{[]byte(""), rr}, nil, nil, nil, true},
		{"failNilPassword", args{nil, rr}, nil, nil, nil, true},
		{"failEOF", args{[]byte("planned password"), eofReader{}}, nil, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rand.Reader = tt.args.randReader
			jose.RandReader = tt.args.randReader
			got, got1, err := GenerateDefaultKeyPair(tt.args.passphrase)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateDefaultKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateDefaultKeyPair() got = %#v, want %#v", got, tt.want)
			}

			if !reflect.DeepEqual(got1, tt.want1) {
				data, err := Decrypt([]byte(got1.FullSerialize()), WithPassword(tt.args.passphrase))
				if err != nil {
					t.Fatalf("json.Marshal() error = %v", err)
				}
				var jwk JSONWebKey
				if err = json.Unmarshal(data, &jwk); err != nil {
					t.Log(string(data))
					t.Fatalf("json.Unmarshal() error = %v", err)
				}

				if !reflect.DeepEqual(&jwk, fixJWK(tt.want1Decrypted)) {
					t.Errorf("GenerateDefaultKeyPair() jwk = %#v, want %#v", &jwk, fixJWK(tt.want1Decrypted))
				}
			}
		})
	}
}
