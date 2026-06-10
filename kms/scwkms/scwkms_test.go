package scwkms

import (
	"context"
	"fmt"
	"os"
	"testing"

	km "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

const testKeyID = "11111111-2222-3333-4444-555555555555"
const testRegion = scw.RegionFrPar

func testKeyURI(keyID string) string {
	return keyIDToURI(keyID, testRegion)
}

func TestNew(t *testing.T) {
	// Override the client constructor to avoid real Scaleway calls.
	orig := newKeyManagerClientFunc
	t.Cleanup(func() { newKeyManagerClientFunc = orig })
	newKeyManagerClientFunc = func(client *scw.Client) KeyManagementClient {
		return &MockClient{}
	}

	tests := []struct {
		name    string
		opts    apiv1.Options
		wantErr bool
	}{
		{"ok/no-uri", apiv1.Options{}, false},
		{"ok/empty-uri", apiv1.Options{URI: "scwkms:"}, false},
		{"ok/uri-with-key", apiv1.Options{URI: "scwkms:key-id=" + testKeyID + ";region=fr-par"}, false},
		{"fail/wrong-scheme", apiv1.Options{URI: "cloudkms:"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := New(context.Background(), tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, k)
		})
	}
}

func TestNewScalewayKMS(t *testing.T) {
	client := &MockClient{}
	k := NewScalewayKMS(client)
	assert.NotNil(t, k)
}

func TestScalewayKMS_Close(t *testing.T) {
	k := &ScalewayKMS{client: &MockClient{}}
	assert.NoError(t, k.Close())
}

func TestScalewayKMS_GetPublicKey(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)

	keyURI := testKeyURI(testKeyID)

	tests := []struct {
		name    string
		client  *MockClient
		req     *apiv1.GetPublicKeyRequest
		wantErr bool
	}{
		{
			name: "ok/key-id",
			client: &MockClient{
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					assert.Equal(t, testKeyID, req.KeyID)
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
			req: &apiv1.GetPublicKeyRequest{Name: testKeyID},
		},
		{
			name: "ok/uri",
			client: &MockClient{
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					assert.Equal(t, testKeyID, req.KeyID)
					assert.Equal(t, testRegion, req.Region)
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
			req: &apiv1.GetPublicKeyRequest{Name: keyURI},
		},
		{
			name:    "fail/empty-name",
			client:  &MockClient{},
			req:     &apiv1.GetPublicKeyRequest{},
			wantErr: true,
		},
		{
			name: "fail/api-error",
			client: &MockClient{
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			req:     &apiv1.GetPublicKeyRequest{Name: testKeyID},
			wantErr: true,
		},
		{
			name: "fail/bad-pem",
			client: &MockClient{
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: "not a pem"}, nil
				},
			},
			req:     &apiv1.GetPublicKeyRequest{Name: testKeyID},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ScalewayKMS{client: tt.client, region: testRegion}
			got, err := k.GetPublicKey(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, pk, got)
		})
	}
}

func TestScalewayKMS_CreateSigner(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)

	signingAlgo := km.KeyAlgorithmAsymmetricSigningEcP256Sha256
	client := &MockClient{
		getKey: func(req *km.GetKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
			return &km.Key{Usage: &km.KeyUsage{AsymmetricSigning: &signingAlgo}}, nil
		},
		getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
			return &km.PublicKey{Pem: string(pemBytes)}, nil
		},
	}

	k := &ScalewayKMS{client: client, region: testRegion}
	signer, err := k.CreateSigner(&apiv1.CreateSignerRequest{SigningKey: testKeyID})
	assert.NoError(t, err)
	assert.NotNil(t, signer)

	// Empty signing key must fail.
	_, err = k.CreateSigner(&apiv1.CreateSignerRequest{})
	assert.Error(t, err)
}

func TestScalewayKMS_CreateKey(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/pub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)

	tests := []struct {
		name    string
		req     *apiv1.CreateKeyRequest
		client  *MockClient
		wantErr bool
	}{
		{
			name: "ok/default-algo",
			req:  &apiv1.CreateKeyRequest{Name: "my-key"},
			client: &MockClient{
				createKey: func(req *km.CreateKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					assert.Equal(t, "my-key", *req.Name)
					assert.True(t, req.Unprotected)
					return &km.Key{ID: testKeyID, Region: testRegion}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
		},
		{
			name: "ok/ecdsa-p256",
			req:  &apiv1.CreateKeyRequest{Name: "ec-key", SignatureAlgorithm: apiv1.ECDSAWithSHA256},
			client: &MockClient{
				createKey: func(req *km.CreateKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					assert.NotNil(t, req.Usage.AsymmetricSigning)
					assert.Equal(t, km.KeyAlgorithmAsymmetricSigningEcP256Sha256, *req.Usage.AsymmetricSigning)
					return &km.Key{ID: testKeyID, Region: testRegion}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
		},
		{
			name: "ok/rsa-pkcs1-3072",
			req:  &apiv1.CreateKeyRequest{Name: "rsa-key", SignatureAlgorithm: apiv1.SHA256WithRSA, Bits: 3072},
			client: &MockClient{
				createKey: func(req *km.CreateKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					assert.Equal(t, km.KeyAlgorithmAsymmetricSigningRsaPkcs1_3072Sha256, *req.Usage.AsymmetricSigning)
					return &km.Key{ID: testKeyID, Region: testRegion}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
		},
		{
			name: "ok/rsa-pss-default-bits",
			req:  &apiv1.CreateKeyRequest{Name: "rsa-pss-key", SignatureAlgorithm: apiv1.SHA256WithRSAPSS},
			client: &MockClient{
				createKey: func(req *km.CreateKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					// Default bits (0) → 3072
					assert.Equal(t, km.KeyAlgorithmAsymmetricSigningRsaPss3072Sha256, *req.Usage.AsymmetricSigning)
					return &km.Key{ID: testKeyID, Region: testRegion}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
		},
		{
			name:    "fail/empty-name",
			req:     &apiv1.CreateKeyRequest{},
			client:  &MockClient{},
			wantErr: true,
		},
		{
			name:    "fail/unsupported-algo",
			req:     &apiv1.CreateKeyRequest{Name: "k", SignatureAlgorithm: apiv1.ECDSAWithSHA512},
			client:  &MockClient{},
			wantErr: true,
		},
		{
			name:    "fail/unsupported-bits",
			req:     &apiv1.CreateKeyRequest{Name: "k", SignatureAlgorithm: apiv1.SHA256WithRSA, Bits: 1024},
			client:  &MockClient{},
			wantErr: true,
		},
		{
			name: "fail/create-key-api-error",
			req:  &apiv1.CreateKeyRequest{Name: "k", SignatureAlgorithm: apiv1.ECDSAWithSHA256},
			client: &MockClient{
				createKey: func(req *km.CreateKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			wantErr: true,
		},
		{
			name: "fail/get-public-key-error",
			req:  &apiv1.CreateKeyRequest{Name: "k", SignatureAlgorithm: apiv1.ECDSAWithSHA256},
			client: &MockClient{
				createKey: func(req *km.CreateKeyRequest, _ ...scw.RequestOption) (*km.Key, error) {
					return &km.Key{ID: testKeyID, Region: testRegion}, nil
				},
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ScalewayKMS{client: tt.client, region: testRegion}
			got, err := k.CreateKey(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, pk, got.PublicKey)
			assert.Contains(t, got.Name, testKeyID)
			assert.Equal(t, got.Name, got.CreateSignerRequest.SigningKey)
		})
	}
}

func TestScalewayKMS_DeleteKey(t *testing.T) {
	keyURI := testKeyURI(testKeyID)

	tests := []struct {
		name    string
		client  *MockClient
		req     *apiv1.DeleteKeyRequest
		wantErr bool
	}{
		{
			name: "ok",
			client: &MockClient{
				deleteKey: func(req *km.DeleteKeyRequest, _ ...scw.RequestOption) error {
					assert.Equal(t, testKeyID, req.KeyID)
					return nil
				},
			},
			req: &apiv1.DeleteKeyRequest{Name: keyURI},
		},
		{
			name:    "fail/empty-name",
			client:  &MockClient{},
			req:     &apiv1.DeleteKeyRequest{},
			wantErr: true,
		},
		{
			name: "fail/api-error",
			client: &MockClient{
				deleteKey: func(req *km.DeleteKeyRequest, _ ...scw.RequestOption) error {
					return fmt.Errorf("protected key")
				},
			},
			req:     &apiv1.DeleteKeyRequest{Name: testKeyID},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ScalewayKMS{client: tt.client, region: testRegion}
			err := k.DeleteKey(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestParseKeyName(t *testing.T) {
	const defaultRegion = scw.RegionFrPar

	tests := []struct {
		name       string
		input      string
		wantKeyID  string
		wantRegion scw.Region
	}{
		{"bare-uuid", testKeyID, testKeyID, defaultRegion},
		{"uri-with-params", "scwkms:key-id=" + testKeyID + ";region=nl-ams", testKeyID, "nl-ams"},
		{"opaque-uri", "scwkms:" + testKeyID, testKeyID, defaultRegion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyID, region := parseKeyName(tt.input, defaultRegion)
			assert.Equal(t, tt.wantKeyID, keyID)
			assert.Equal(t, tt.wantRegion, region)
		})
	}
}
