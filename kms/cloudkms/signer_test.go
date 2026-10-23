package cloudkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/pemutil"
)

func Test_NewSigner(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)

	type args struct {
		c          KeyManagementClient
		signingKey string
	}
	tests := []struct {
		name    string
		args    args
		want    *Signer
		wantErr bool
	}{
		{"ok", args{&MockClient{
			getPublicKey: func(_ context.Context, r *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				assert.NotContains(t, r.Name, "cloudkms:")
				return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
			},
		}, "signingKey"}, &Signer{client: &MockClient{}, signingKey: "signingKey", publicKey: pk}, false},
		{"ok with uri", args{&MockClient{
			getPublicKey: func(_ context.Context, r *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				assert.NotContains(t, r.Name, "cloudkms:")
				return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
			},
		}, "cloudkms:resource=signingKey"}, &Signer{client: &MockClient{}, signingKey: "signingKey", publicKey: pk}, false},
		{"ok with opaque uri", args{&MockClient{
			getPublicKey: func(_ context.Context, r *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				assert.NotContains(t, r.Name, "cloudkms:")
				return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
			},
		}, "cloudkms:signingKey"}, &Signer{client: &MockClient{}, signingKey: "signingKey", publicKey: pk}, false},
		{"fail get public key", args{&MockClient{
			getPublicKey: func(_ context.Context, r *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				assert.NotContains(t, r.Name, "cloudkms:")
				return nil, fmt.Errorf("an error")
			},
		}, "signingKey"}, nil, true},
		{"fail parse pem", args{&MockClient{
			getPublicKey: func(_ context.Context, r *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				assert.NotContains(t, r.Name, "cloudkms:")
				return &kmspb.PublicKey{Pem: string("bad pem")}, nil
			},
		}, "signingKey"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.args.c, tt.args.signingKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				got.client = &MockClient{}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_signer_Public(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)

	type fields struct {
		client     KeyManagementClient
		signingKey string
		publicKey  crypto.PublicKey
	}
	tests := []struct {
		name   string
		fields fields
		want   crypto.PublicKey
	}{
		{"ok", fields{&MockClient{}, "signingKey", pk}, pk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:     tt.fields.client,
				signingKey: tt.fields.signingKey,
				publicKey:  tt.fields.publicKey,
			}
			if got := s.Public(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("signer.Public() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_signer_Sign(t *testing.T) {
	keyName := "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"
	okClient := &MockClient{
		asymmetricSign: func(_ context.Context, r *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
			assert.NotContains(t, r.Name, "cloudkms:")
			return &kmspb.AsymmetricSignResponse{Signature: []byte("ok signature")}, nil
		},
	}
	failClient := &MockClient{
		asymmetricSign: func(_ context.Context, r *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
			assert.NotContains(t, r.Name, "cloudkms:")
			return nil, fmt.Errorf("an error")
		},
	}

	type fields struct {
		client     KeyManagementClient
		signingKey string
	}
	type args struct {
		rand   io.Reader
		digest []byte
		opts   crypto.SignerOpts
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok sha256", fields{okClient, keyName}, args{rand.Reader, []byte("digest"), crypto.SHA256}, []byte("ok signature"), false},
		{"ok sha384", fields{okClient, keyName}, args{rand.Reader, []byte("digest"), crypto.SHA384}, []byte("ok signature"), false},
		{"ok sha512", fields{okClient, keyName}, args{rand.Reader, []byte("digest"), crypto.SHA512}, []byte("ok signature"), false},
		{"fail MD5", fields{okClient, keyName}, args{rand.Reader, []byte("digest"), crypto.MD5}, nil, true},
		{"fail asymmetric sign", fields{failClient, keyName}, args{rand.Reader, []byte("digest"), crypto.SHA256}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:     tt.fields.client,
				signingKey: tt.fields.signingKey,
			}
			got, err := s.Sign(tt.args.rand, tt.args.digest, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("signer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("signer.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_signer_Sign_nilOpts(t *testing.T) {
	keyName := "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"
	client := &MockClient{
		asymmetricSign: func(_ context.Context, r *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
			var b []byte
			switch {
			case r.Digest.GetSha256() != nil:
				b = append([]byte("sha256:"), r.Digest.GetSha256()...)
			case r.Digest.GetSha384() != nil:
				b = append([]byte("sha384:"), r.Digest.GetSha384()...)
			case r.Digest.GetSha512() != nil:
				b = append([]byte("sha512:"), r.Digest.GetSha512()...)
			default:
				b = append([]byte("data:"), r.Data...)
			}
			return &kmspb.AsymmetricSignResponse{Signature: b}, nil
		},
	}

	p256 := &ecdsa.PublicKey{Curve: elliptic.P256()}
	p384 := &ecdsa.PublicKey{Curve: elliptic.P384()}
	p521 := &ecdsa.PublicKey{Curve: elliptic.P521()}
	sha256Digest := bytes.Repeat([]byte{1}, 32)
	sha384Digest := bytes.Repeat([]byte{2}, 48)
	sha512Digest := bytes.Repeat([]byte{3}, 64)

	tests := []struct {
		name      string
		publicKey crypto.PublicKey
		digest    []byte
		want      []byte
		wantErr   bool
	}{
		{"ok P-256", p256, sha256Digest, append([]byte("sha256:"), sha256Digest...), false},
		{"ok P-384", p384, sha384Digest, append([]byte("sha384:"), sha384Digest...), false},
		{"ok P-521", p521, sha512Digest, append([]byte("sha512:"), sha512Digest...), false},
		{"ok P-256 truncated", p256, sha384Digest, append([]byte("sha256:"), sha384Digest[:32]...), false},
		{"ok P-384 padded", p384, sha256Digest, append([]byte("sha384:"), append(make([]byte, 16), sha256Digest...)...), false},
		{"ok P-521 padded", p521, sha256Digest[:16], append([]byte("sha512:"), append(make([]byte, 48), sha256Digest[:16]...)...), false},
		{"ok P-384 truncated", p384, append(append([]byte{}, sha384Digest...), make([]byte, 18)...), append([]byte("sha384:"), sha384Digest...), false},
		{"ok ed25519", ed25519.PublicKey{}, []byte("message"), []byte("data:message"), false},
		{"fail P-521 digest length", p521, make([]byte, 66), nil, true},
		{"fail empty digest", p256, nil, nil, true},
		{"fail rsa", &rsa.PublicKey{}, sha256Digest, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:     client,
				signingKey: keyName,
				publicKey:  tt.publicKey,
			}
			got, err := s.Sign(rand.Reader, tt.digest, nil)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSigner_SignatureAlgorithm(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)

	client := &MockClient{
		getPublicKey: func(_ context.Context, req *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
			var algorithm kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
			switch req.Name {
			case "ECDSA-SHA256":
				algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256
			case "ECDSA-SHA384":
				algorithm = kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384
			case "SHA256-RSA-2048":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256
			case "SHA256-RSA-3072":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256
			case "SHA256-RSA-4096":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256
			case "SHA512-RSA-4096":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512
			case "SHA256-RSAPSS-2048":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256
			case "SHA256-RSAPSS-3072":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256
			case "SHA256-RSAPSS-4096":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256
			case "SHA512-RSAPSS-4096":
				algorithm = kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512
			}
			return &kmspb.PublicKey{
				Pem:       string(pemBytes),
				Algorithm: algorithm,
			}, nil
		},
	}

	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		client     KeyManagementClient
		signingKey string
	}
	tests := []struct {
		name   string
		fields fields
		want   x509.SignatureAlgorithm
	}{
		{"ECDSA-SHA256", fields{client, "ECDSA-SHA256"}, x509.ECDSAWithSHA256},
		{"ECDSA-SHA384", fields{client, "ECDSA-SHA384"}, x509.ECDSAWithSHA384},
		{"SHA256-RSA-2048", fields{client, "SHA256-RSA-2048"}, x509.SHA256WithRSA},
		{"SHA256-RSA-3072", fields{client, "SHA256-RSA-3072"}, x509.SHA256WithRSA},
		{"SHA256-RSA-4096", fields{client, "SHA256-RSA-4096"}, x509.SHA256WithRSA},
		{"SHA512-RSA-4096", fields{client, "SHA512-RSA-4096"}, x509.SHA512WithRSA},
		{"SHA256-RSAPSS-2048", fields{client, "SHA256-RSAPSS-2048"}, x509.SHA256WithRSAPSS},
		{"SHA256-RSAPSS-3072", fields{client, "SHA256-RSAPSS-3072"}, x509.SHA256WithRSAPSS},
		{"SHA256-RSAPSS-4096", fields{client, "SHA256-RSAPSS-4096"}, x509.SHA256WithRSAPSS},
		{"SHA512-RSAPSS-4096", fields{client, "SHA512-RSAPSS-4096"}, x509.SHA512WithRSAPSS},
		{"unknown", fields{client, "UNKNOWN"}, x509.UnknownSignatureAlgorithm},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.fields.client, tt.fields.signingKey)
			if err != nil {
				t.Errorf("NewSigner() error = %v", err)
			}
			if got := signer.SignatureAlgorithm(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.SignatureAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}
