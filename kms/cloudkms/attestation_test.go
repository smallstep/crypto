package cloudkms

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/minica"
	"go.step.sm/crypto/pemutil"
	"go.step.sm/crypto/randutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func mustContent(t *testing.T, filename string) ([]byte, []AttestationAttribute, []AttestationAttribute) {
	content, err := os.ReadFile(filename)
	require.NoError(t, err)

	r, err := gzip.NewReader(bytes.NewReader(content))
	require.NoError(t, err)
	b, err := io.ReadAll(r)
	require.NoError(t, err)

	pub, priv, err := parseAttestation(b[:len(b)-256])
	require.NoError(t, err)
	return content, pub, priv
}

func mustCerts(t *testing.T, filename string) []string {
	t.Helper()

	certs, err := pemutil.ReadCertificateBundle(filename)
	require.NoError(t, err)

	pemData := make([]string, len(certs))
	for i, crt := range certs {
		pemData[i] = string(pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: crt.Raw,
		}))
	}
	return pemData
}

func mustKeyOperationAttestation(t *testing.T, typ string) *kmspb.KeyOperationAttestation {
	t.Helper()
	content, _, _ := mustContent(t, filepath.Join("testdata", typ+".dat"))
	certs := mustCerts(t, filepath.Join("testdata", typ+".certs"))
	return &kmspb.KeyOperationAttestation{
		Format:  kmspb.KeyOperationAttestation_CAVIUM_V2_COMPRESSED,
		Content: content,
		CertChains: &kmspb.KeyOperationAttestation_CertificateChains{
			CaviumCerts:          []string{certs[1], certs[2]},
			GoogleCardCerts:      []string{certs[4]},
			GooglePartitionCerts: []string{certs[5]},
		},
	}
}

func mustAttestationClient(t *testing.T, typ string) KeyManagementClient {
	t.Helper()
	var alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	switch typ {
	case "ec":
		alg = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
	case "rsa":
		alg = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
	case "aes":
		alg = kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION
	}

	return &MockClient{
		getCryptoKeyVersion: func(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
			return &kmspb.CryptoKeyVersion{
				Name:        req.Name,
				Algorithm:   alg,
				Attestation: mustKeyOperationAttestation(t, typ),
			}, nil
		},
	}
}

func TestCloudKMS_VerifyAttestation(t *testing.T) {
	ecContent, ecPub, ecPriv := mustContent(t, "testdata/ec.dat")
	rsaContent, rsaPub, rsaPriv := mustContent(t, "testdata/rsa.dat")
	aesContent, aesSym, _ := mustContent(t, "testdata/aes.dat")

	ecCerts := mustCerts(t, "testdata/ec.certs")
	rsaCerts := mustCerts(t, "testdata/rsa.certs")
	aesCerts := mustCerts(t, "testdata/aes.certs")

	failClient := &MockClient{
		getCryptoKeyVersion: func(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
	}

	type fields struct {
		client KeyManagementClient
	}
	type args struct {
		ctx  context.Context
		name string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      *Attestation
		assertion assert.ErrorAssertionFunc
	}{
		{"ok ec", fields{mustAttestationClient(t, "ec")}, args{context.Background(), "projects/test-project/locations/test-location/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1"}, &Attestation{
			Valid:       true,
			Generated:   true,
			Extractable: false,
			KeyType:     "EC",
			Algorithm:   "EC_SIGN_P256_SHA256",
			Format:      "CAVIUM_V2_COMPRESSED",
			Content:     ecContent,
			CertChain: &AttestationCertChain{
				ManufacturerRoot:          caviumRoot,
				ManufacturerCardCert:      ecCerts[1],
				ManufacturerPartitionCert: ecCerts[2],
				OwnerRoot:                 googleHawksbillRoot,
				OwnerCardCert:             ecCerts[4],
				OwnerPartitionCert:        ecCerts[5],
			},
			PublicKeyAttributes:  ecPub,
			PrivateKeyAttributes: ecPriv,
		}, assert.NoError},
		{"ok rsa", fields{mustAttestationClient(t, "rsa")}, args{context.Background(), "projects/test-project/locations/test-location/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1"}, &Attestation{
			Valid:       true,
			Generated:   true,
			Extractable: false,
			KeyType:     "RSA 2048",
			Algorithm:   "RSA_SIGN_PSS_2048_SHA256",
			Format:      "CAVIUM_V2_COMPRESSED",
			Content:     rsaContent,
			CertChain: &AttestationCertChain{
				ManufacturerRoot:          caviumRoot,
				ManufacturerCardCert:      rsaCerts[1],
				ManufacturerPartitionCert: rsaCerts[2],
				OwnerRoot:                 googleHawksbillRoot,
				OwnerCardCert:             rsaCerts[4],
				OwnerPartitionCert:        rsaCerts[5],
			},
			PublicKeyAttributes:  rsaPub,
			PrivateKeyAttributes: rsaPriv,
		}, assert.NoError},
		{"ok aes", fields{mustAttestationClient(t, "aes")}, args{context.Background(), "projects/test-project/locations/test-location/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1"}, &Attestation{
			Valid:       true,
			Generated:   true,
			Extractable: false,
			KeyType:     "AES",
			Algorithm:   "GOOGLE_SYMMETRIC_ENCRYPTION",
			Format:      "CAVIUM_V2_COMPRESSED",
			Content:     aesContent,
			CertChain: &AttestationCertChain{
				ManufacturerRoot:          caviumRoot,
				ManufacturerCardCert:      aesCerts[1],
				ManufacturerPartitionCert: aesCerts[2],
				OwnerRoot:                 googleHawksbillRoot,
				OwnerCardCert:             aesCerts[4],
				OwnerPartitionCert:        aesCerts[5],
			},
			SymmetricKeyAttributes: aesSym,
		}, assert.NoError},
		{"fail fail client", fields{failClient}, args{context.Background(), "projects/test-project/locations/test-location/keyRings/test-keyring/cryptoKeys/test-key/cryptoKeyVersions/1"}, nil, assert.Error},
		{"fail regex", fields{mustAttestationClient(t, "ec")}, args{context.Background(), "projects/test-project/locations/test-location/keyRings/test-keyring/cryptoKeys/test-key"}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &CloudKMS{
				client: tt.fields.client,
			}
			got, err := k.VerifyAttestation(tt.args.ctx, tt.args.name)
			tt.assertion(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCloudKMS_verifyAttestation(t *testing.T) {
	ca, err := minica.New()
	require.NoError(t, err)
	caRoot := string(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: ca.Root.Raw,
	}))

	content, pub, priv := mustContent(t, "testdata/ec.dat")
	certs := mustCerts(t, "testdata/ec.certs")

	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	data, err := randutil.Salt(1000)
	require.NoError(t, err)
	_, err = w.Write(data)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	contentGarbage := buf.Bytes()

	client := mustAttestationClient(t, "ec")
	failClient := &MockClient{
		getCryptoKeyVersion: func(context.Context, *kmspb.GetCryptoKeyVersionRequest, ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
	}
	failClientEmpty := &MockClient{
		getCryptoKeyVersion: func(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
			return &kmspb.CryptoKeyVersion{
				Name: req.Name,
			}, nil
		},
	}
	failClientFormat := &MockClient{
		getCryptoKeyVersion: func(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
			att := mustKeyOperationAttestation(t, "ec")
			att.Format = kmspb.KeyOperationAttestation_ATTESTATION_FORMAT_UNSPECIFIED
			return &kmspb.CryptoKeyVersion{
				Name:        req.Name,
				Attestation: att,
			}, nil
		},
	}

	mustClientWithContent := func(t *testing.T, content []byte) KeyManagementClient {
		t.Helper()
		return &MockClient{
			getCryptoKeyVersion: func(_ context.Context, req *kmspb.GetCryptoKeyVersionRequest, _ ...gax.CallOption) (*kmspb.CryptoKeyVersion, error) {
				att := mustKeyOperationAttestation(t, "ec")
				att.Content = content
				return &kmspb.CryptoKeyVersion{
					Name:        req.Name,
					Attestation: att,
				}, nil
			},
		}
	}

	type fields struct {
		client KeyManagementClient
	}
	type args struct {
		ctx          context.Context
		name         string
		mfrRootPEM   string
		ownerRootPEM string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		want      *Attestation
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", fields{client}, args{context.Background(), "the-name", caviumRoot, googleHawksbillRoot}, &Attestation{
			Valid:       true,
			Generated:   true,
			Extractable: false,
			KeyType:     "EC",
			Algorithm:   "EC_SIGN_P256_SHA256",
			Format:      "CAVIUM_V2_COMPRESSED",
			Content:     content,
			CertChain: &AttestationCertChain{
				ManufacturerRoot:          caviumRoot,
				ManufacturerCardCert:      certs[1],
				ManufacturerPartitionCert: certs[2],
				OwnerRoot:                 googleHawksbillRoot,
				OwnerCardCert:             certs[4],
				OwnerPartitionCert:        certs[5],
			},
			PublicKeyAttributes:  pub,
			PrivateKeyAttributes: priv,
		}, assert.NoError},
		{"fail client response", fields{failClient}, args{context.Background(), "the-name", caviumRoot, googleHawksbillRoot}, nil, assert.Error},
		{"fail attestation empty", fields{failClientEmpty}, args{context.Background(), "the-name", caviumRoot, googleHawksbillRoot}, nil, assert.Error},
		{"fail attestation format", fields{failClientFormat}, args{context.Background(), "the-name", caviumRoot, googleHawksbillRoot}, nil, assert.Error},
		{"fail manufacturer validation", fields{client}, args{context.Background(), "the-name", caRoot, googleHawksbillRoot}, nil, assert.Error},
		{"fail owner validation", fields{client}, args{context.Background(), "the-name", caviumRoot, caRoot}, nil, assert.Error},
		{"fail gzip", fields{mustClientWithContent(t, []byte("garbage"))}, args{context.Background(), "the-name", caviumRoot, caRoot}, nil, assert.Error},
		{"fail gzip garbage", fields{mustClientWithContent(t, contentGarbage)}, args{context.Background(), "the-name", caviumRoot, googleHawksbillRoot}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &CloudKMS{
				client: tt.fields.client,
			}
			got, err := k.verifyAttestation(tt.args.ctx, tt.args.name, tt.args.mfrRootPEM, tt.args.ownerRootPEM)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_decode(t *testing.T) {
	type args struct {
		data     []byte
		dest     any
		wantSize int
	}
	tests := []struct {
		name      string
		args      args
		assert    func(*testing.T, any) bool
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{[]byte{0x01, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x01}, &[2]uint32{}, 8}, func(t *testing.T, v any) bool {
			vv, ok := v.(*[2]uint32)
			return assert.True(t, ok) && assert.Equal(t, [2]uint32{0x1020304, 0x4030201}, *vv)
		}, assert.NoError},
		{"fail buff", args{[]byte{0x01, 0x02, 0x03, 0x04, 0x04, 0x03, 0x02, 0x01}, &[1]uint32{}, 8}, func(t *testing.T, v any) bool {
			vv, ok := v.(*[1]uint32)
			return assert.True(t, ok) && assert.Equal(t, [1]uint32{0x1020304}, *vv)
		}, assert.Error},
		{"fail size", args{[]byte{0x01, 0x02, 0x03, 0x04}, &[2]uint32{}, 8}, func(t *testing.T, v any) bool {
			vv, ok := v.(*[2]uint32)
			return assert.True(t, ok) && assert.Equal(t, [2]uint32{0x00, 0x00}, *vv)
		}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, decode(tt.args.data, tt.args.dest, tt.args.wantSize))
			tt.assert(t, tt.args.dest)
		})
	}
}

func Test_getKeyType(t *testing.T) {
	tests := []struct {
		name string
		v    uint32
		want string
	}{
		{"RSA", 0x0000, "RSA"},
		{"DSA", 0x0001, "DSA"},
		{"DH", 0x0002, "DH"},
		{"EC", 0x0003, "EC"},
		{"X9_42_DH", 0x0004, "X9_42_DH"},
		{"KEA", 0x0005, "KEA"},
		{"GENERIC_SECRET", 0x0010, "GENERIC_SECRET"},
		{"RC2", 0x0011, "RC2"},
		{"RC4", 0x0012, "RC4"},
		{"DES", 0x0013, "DES"},
		{"DES2", 0x0014, "DES2"},
		{"DES3", 0x0015, "DES3"},
		{"CAST", 0x0016, "CAST"},
		{"CAST3", 0x0017, "CAST3"},
		{"CAST128", 0x0018, "CAST128"},
		{"RC5", 0x0019, "RC5"},
		{"IDEA", 0x001A, "IDEA"},
		{"SKIPJACK", 0x001B, "SKIPJACK"},
		{"BATON", 0x001C, "BATON"},
		{"JUNIPER", 0x001D, "JUNIPER"},
		{"CDMF", 0x001E, "CDMF"},
		{"AES", 0x001F, "AES"},
		{"BLOWFISH", 0x0020, "BLOWFISH"},
		{"TWOFISH", 0x0021, "TWOFISH"},
		{"SECURID", 0x0022, "SECURID"},
		{"HOTP", 0x0023, "HOTP"},
		{"ACTI", 0x0024, "ACTI"},
		{"CAMELLIA", 0x0025, "CAMELLIA"},
		{"ARIA", 0x0026, "ARIA"},
		{"MD5_HMAC", 0x0027, "MD5_HMAC"},
		{"SHA_1_HMAC", 0x0028, "SHA_1_HMAC"},
		{"RIPEMD128_HMAC", 0x0029, "RIPEMD128_HMAC"},
		{"RIPEMD160_HMAC", 0x002A, "RIPEMD160_HMAC"},
		{"SHA256_HMAC", 0x002B, "SHA256_HMAC"},
		{"SHA384_HMAC", 0x002C, "SHA384_HMAC"},
		{"SHA512_HMAC", 0x002D, "SHA512_HMAC"},
		{"SHA224_HMAC", 0x002E, "SHA224_HMAC"},
		{"SEED", 0x002F, "SEED"},
		{"GOSTR3410", 0x0030, "GOSTR3410"},
		{"GOSTR3411", 0x0031, "GOSTR3411"},
		{"GOST28147", 0x0032, "GOST28147"},
		{"VENDOR_DEFINED", 0x80000000, "VENDOR_DEFINED"},
		{"UNKNOWN", 0x33, "UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, getKeyType(tt.v))
		})
	}
}

func TestValidateCaviumRoot(t *testing.T) {
	root, err := pemutil.ParseCertificate([]byte(caviumRoot))
	require.NoError(t, err)

	resp, err := http.Get("https://www.marvell.com/content/dam/marvell/en/public-collateral/security-solutions/liquid_security_certificate.zip")
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, resp.Body.Close())
	})

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	require.NoError(t, err)

	for _, f := range r.File {
		if f.Name == "liquid_security_certificate.crt" {
			rc, err := f.Open()
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, rc.Close())
			})
			b, err = io.ReadAll(rc)
			require.NoError(t, err)

			cert, err := pemutil.ParseCertificate(b)
			require.NoError(t, err)

			assert.Equal(t, root, cert)
			return
		}
	}

	t.Error("certificate not found")
}

func Test_isSymmetric(t *testing.T) {
	type args struct {
		alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED", args{kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED}, false},
		{"GOOGLE_SYMMETRIC_ENCRYPTION", args{kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION}, true},
		{"AES_128_GCM", args{kmspb.CryptoKeyVersion_AES_128_GCM}, true},
		{"AES_256_GCM", args{kmspb.CryptoKeyVersion_AES_256_GCM}, true},
		{"AES_128_CBC", args{kmspb.CryptoKeyVersion_AES_128_CBC}, true},
		{"AES_256_CBC", args{kmspb.CryptoKeyVersion_AES_256_CBC}, true},
		{"AES_128_CTR", args{kmspb.CryptoKeyVersion_AES_128_CTR}, true},
		{"AES_256_CTR", args{kmspb.CryptoKeyVersion_AES_256_CTR}, true},
		{"RSA_SIGN_PSS_2048_SHA256", args{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256}, false},
		{"RSA_SIGN_PSS_3072_SHA256", args{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256}, false},
		{"RSA_SIGN_PSS_4096_SHA256", args{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256}, false},
		{"RSA_SIGN_PSS_4096_SHA512", args{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512}, false},
		{"RSA_SIGN_PKCS1_2048_SHA256", args{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256}, false},
		{"RSA_SIGN_PKCS1_3072_SHA256", args{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256}, false},
		{"RSA_SIGN_PKCS1_4096_SHA256", args{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256}, false},
		{"RSA_SIGN_PKCS1_4096_SHA512", args{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512}, false},
		{"RSA_SIGN_RAW_PKCS1_2048", args{kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048}, false},
		{"RSA_SIGN_RAW_PKCS1_3072", args{kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_3072}, false},
		{"RSA_SIGN_RAW_PKCS1_4096", args{kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_4096}, false},
		{"RSA_DECRYPT_OAEP_2048_SHA256", args{kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256}, false},
		{"RSA_DECRYPT_OAEP_3072_SHA256", args{kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256}, false},
		{"RSA_DECRYPT_OAEP_4096_SHA256", args{kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256}, false},
		{"RSA_DECRYPT_OAEP_4096_SHA512", args{kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA512}, false},
		{"RSA_DECRYPT_OAEP_2048_SHA1", args{kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA1}, false},
		{"RSA_DECRYPT_OAEP_3072_SHA1", args{kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA1}, false},
		{"RSA_DECRYPT_OAEP_4096_SHA1", args{kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA1}, false},
		{"EC_SIGN_P256_SHA256", args{kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256}, false},
		{"EC_SIGN_P384_SHA384", args{kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384}, false},
		{"EC_SIGN_SECP256K1_SHA256", args{kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256}, false},
		{"EC_SIGN_ED25519", args{kmspb.CryptoKeyVersion_EC_SIGN_ED25519}, false},
		{"HMAC_SHA256", args{kmspb.CryptoKeyVersion_HMAC_SHA256}, true},
		{"HMAC_SHA1", args{kmspb.CryptoKeyVersion_HMAC_SHA1}, true},
		{"HMAC_SHA384", args{kmspb.CryptoKeyVersion_HMAC_SHA384}, true},
		{"HMAC_SHA512", args{kmspb.CryptoKeyVersion_HMAC_SHA512}, true},
		{"HMAC_SHA224", args{kmspb.CryptoKeyVersion_HMAC_SHA224}, true},
		{"EXTERNAL_SYMMETRIC_ENCRYPTION", args{kmspb.CryptoKeyVersion_EXTERNAL_SYMMETRIC_ENCRYPTION}, true},
		{"PQ_SIGN_ML_DSA_65", args{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65}, false},
		{"PQ_SIGN_SLH_DSA_SHA2_128S", args{kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isSymmetric(tt.args.alg))
		})
	}
}
