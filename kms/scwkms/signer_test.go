package scwkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	km "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/pemutil"
)

func TestNewSigner(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)

	signingAlgo := km.KeyAlgorithmAsymmetricSigningEcP256Sha256

	tests := []struct {
		name       string
		client     *MockClient
		signingKey string
		wantErr    bool
		wantAlg    x509.SignatureAlgorithm
	}{
		{
			name: "ok/bare-id",
			client: &MockClient{
				getKey: func(req *km.GetKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					assert.Equal(t, testKeyID, req.KeyID)
					return &km.Key{Usage: &km.KeyUsage{AsymmetricSigning: &signingAlgo}}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					assert.Equal(t, testKeyID, req.KeyID)
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
			signingKey: testKeyID,
			wantAlg:    x509.ECDSAWithSHA256,
		},
		{
			name: "ok/uri",
			client: &MockClient{
				getKey: func(req *km.GetKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					assert.Equal(t, testKeyID, req.KeyID)
					return &km.Key{Usage: &km.KeyUsage{AsymmetricSigning: &signingAlgo}}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
			signingKey: testKeyURI(testKeyID),
			wantAlg:    x509.ECDSAWithSHA256,
		},
		{
			name: "fail/get-key-error",
			client: &MockClient{
				getKey: func(req *km.GetKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			signingKey: testKeyID,
			wantErr:    true,
		},
		{
			name: "fail/get-public-key-error",
			client: &MockClient{
				getKey: func(req *km.GetKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					return &km.Key{Usage: &km.KeyUsage{AsymmetricSigning: &signingAlgo}}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			signingKey: testKeyID,
			wantErr:    true,
		},
		{
			name: "fail/bad-pem",
			client: &MockClient{
				getKey: func(req *km.GetKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					return &km.Key{Usage: &km.KeyUsage{AsymmetricSigning: &signingAlgo}}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: "not a pem"}, nil
				},
			},
			signingKey: testKeyID,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := NewSigner(tt.client, tt.signingKey)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, pk, signer.Public())
			assert.Equal(t, tt.wantAlg, signer.SignatureAlgorithm())
		})
	}
}

func TestSigner_SignatureAlgorithm(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)

	algos := []struct {
		algo    km.KeyAlgorithmAsymmetricSigning
		wantAlg x509.SignatureAlgorithm
	}{
		{km.KeyAlgorithmAsymmetricSigningEcP256Sha256, x509.ECDSAWithSHA256},
		{km.KeyAlgorithmAsymmetricSigningEcP384Sha384, x509.ECDSAWithSHA384},
		{km.KeyAlgorithmAsymmetricSigningRsaPkcs1_2048Sha256, x509.SHA256WithRSA},
		{km.KeyAlgorithmAsymmetricSigningRsaPkcs1_3072Sha256, x509.SHA256WithRSA},
		{km.KeyAlgorithmAsymmetricSigningRsaPkcs1_4096Sha256, x509.SHA256WithRSA},
		{km.KeyAlgorithmAsymmetricSigningRsaPss2048Sha256, x509.SHA256WithRSAPSS},
		{km.KeyAlgorithmAsymmetricSigningRsaPss3072Sha256, x509.SHA256WithRSAPSS},
		{km.KeyAlgorithmAsymmetricSigningRsaPss4096Sha256, x509.SHA256WithRSAPSS},
	}

	for _, tc := range algos {
		t.Run(string(tc.algo), func(t *testing.T) {
			a := tc.algo
			client := &MockClient{
				getKey: func(req *km.GetKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					return &km.Key{Usage: &km.KeyUsage{AsymmetricSigning: &a}}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			}
			signer, err := NewSigner(client, testKeyID)
			require.NoError(t, err)
			assert.Equal(t, tc.wantAlg, signer.SignatureAlgorithm())
		})
	}
}

func TestSigner_Public(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)

	s := &Signer{publicKey: pk}
	assert.Equal(t, pk, s.Public())
}

func TestSigner_Sign(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)
	ecPub, ok := pk.(*ecdsa.PublicKey)
	require.True(t, ok)

	digest := []byte("0123456789abcdef0123456789abcdef") // 32-byte SHA-256

	// A valid DER-encoded signature to use as mock return.
	derSig := makeDERSignature(t)

	tests := []struct {
		name    string
		client  *MockClient
		digest  []byte
		opts    crypto.SignerOpts
		wantErr bool
	}{
		{
			name: "ok/sha256",
			client: &MockClient{
				sign: func(req *km.SignRequest, _ ...scw.RequestOption) (*km.SignResponse, error) {
					assert.Equal(t, digest, req.Digest)
					return &km.SignResponse{Signature: derSig}, nil
				},
			},
			digest: digest,
			opts:   crypto.SHA256,
		},
		{
			name: "ok/raw-p1363-normalised",
			client: &MockClient{
				sign: func(req *km.SignRequest, _ ...scw.RequestOption) (*km.SignResponse, error) {
					// Return a raw P-1363 signature (64 bytes for P-256).
					rawSig := make([]byte, 64)
					copy(rawSig[:32], digest)
					copy(rawSig[32:], digest)
					return &km.SignResponse{Signature: rawSig}, nil
				},
			},
			digest: digest,
			opts:   crypto.SHA256,
		},
		{
			name:    "fail/unsupported-hash",
			client:  &MockClient{},
			digest:  digest,
			opts:    crypto.MD5,
			wantErr: true,
		},
		{
			name: "fail/api-error",
			client: &MockClient{
				sign: func(req *km.SignRequest, _ ...scw.RequestOption) (*km.SignResponse, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			digest:  digest,
			opts:    crypto.SHA256,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:    tt.client,
				keyID:     testKeyID,
				region:    testRegion,
				publicKey: ecPub,
				algorithm: x509.ECDSAWithSHA256,
			}
			got, err := s.Sign(rand.Reader, tt.digest, tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, got)
		})
	}
}

func TestNormalizeECDSASignature(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub := &privKey.PublicKey

	// Create a 64-byte raw P-1363 signature.
	rawR := make([]byte, 32)
	rawS := make([]byte, 32)
	_, _ = rand.Read(rawR)
	_, _ = rand.Read(rawS)
	rawSig := make([]byte, 0, 64)
	rawSig = append(rawSig, rawR...)
	rawSig = append(rawSig, rawS...)

	// Normalise: should produce a DER sequence.
	der, err := normalizeECDSASignature(rawSig, pub)
	require.NoError(t, err)
	assert.Greater(t, len(der), 64, "DER encoding should add overhead")
	assert.Equal(t, byte(0x30), der[0], "DER sequence tag should be 0x30")

	// Already DER (wrong length for raw): should return unchanged.
	shortSig := []byte{0x30, 0x44, 0x02, 0x20} // 4 bytes, not 64
	result, err := normalizeECDSASignature(shortSig, pub)
	require.NoError(t, err)
	assert.Equal(t, shortSig, result)
}

// makeDERSignature creates a small valid DER ECDSA signature for testing.
func makeDERSignature(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	digest := make([]byte, 32)
	_, err = rand.Read(digest)
	require.NoError(t, err)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest)
	require.NoError(t, err)
	return sig
}

// Ensure Signer satisfies crypto.Signer at compile time.
var _ crypto.Signer = (*Signer)(nil)
