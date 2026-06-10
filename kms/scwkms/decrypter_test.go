package scwkms

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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

func TestScalewayKMS_CreateDecrypter(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/rsapub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)

	tests := []struct {
		name    string
		client  *MockClient
		req     *apiv1.CreateDecrypterRequest
		wantErr bool
	}{
		{
			name: "ok",
			client: &MockClient{
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					assert.Equal(t, testKeyID, req.KeyID)
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
			req: &apiv1.CreateDecrypterRequest{DecryptionKey: testKeyID},
		},
		{
			name:    "fail/empty-key",
			client:  &MockClient{},
			req:     &apiv1.CreateDecrypterRequest{},
			wantErr: true,
		},
		{
			name: "fail/api-error",
			client: &MockClient{
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			req:     &apiv1.CreateDecrypterRequest{DecryptionKey: testKeyID},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &ScalewayKMS{client: tt.client, region: testRegion}
			got, err := k.CreateDecrypter(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, pk, got.Public())
		})
	}
}

func TestNewDecrypter(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/rsapub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)

	tests := []struct {
		name    string
		client  *MockClient
		key     string
		wantErr bool
	}{
		{
			name: "ok",
			client: &MockClient{
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: string(pemBytes)}, nil
				},
			},
			key: testKeyID,
		},
		{
			name: "fail/api-error",
			client: &MockClient{
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			key:     testKeyID,
			wantErr: true,
		},
		{
			name: "fail/bad-pem",
			client: &MockClient{
				getPublicKey: func(req *km.GetPublicKeyRequest, _ ...scw.RequestOption) (*km.PublicKey, error) {
					return &km.PublicKey{Pem: "not a pem"}, nil
				},
			},
			key:     testKeyID,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDecrypter(tt.client, tt.key)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, pk, d.Public())
		})
	}
}

func TestDecrypter_Decrypt(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/rsapub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)

	plaintext := []byte("hello")

	var nilOpts *rsa.OAEPOptions

	tests := []struct {
		name    string
		client  *MockClient
		opts    crypto.DecrypterOpts
		wantErr bool
	}{
		{
			name: "ok/nil-opts",
			client: &MockClient{
				decrypt: func(req *km.DecryptRequest, _ ...scw.RequestOption) (*km.DecryptResponse, error) {
					assert.Nil(t, req.AssociatedData)
					return &km.DecryptResponse{Plaintext: plaintext}, nil
				},
			},
		},
		{
			name: "ok/nil-oaep-opts",
			client: &MockClient{
				decrypt: func(req *km.DecryptRequest, _ ...scw.RequestOption) (*km.DecryptResponse, error) {
					return &km.DecryptResponse{Plaintext: plaintext}, nil
				},
			},
			opts: nilOpts,
		},
		{
			name: "ok/sha256-oaep",
			client: &MockClient{
				decrypt: func(req *km.DecryptRequest, _ ...scw.RequestOption) (*km.DecryptResponse, error) {
					return &km.DecryptResponse{Plaintext: plaintext}, nil
				},
			},
			opts: &rsa.OAEPOptions{Hash: crypto.SHA256},
		},
		{
			name:    "fail/label",
			client:  &MockClient{},
			opts:    &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("label")},
			wantErr: true,
		},
		{
			name:    "fail/unsupported-hash",
			client:  &MockClient{},
			opts:    &rsa.OAEPOptions{Hash: crypto.SHA512},
			wantErr: true,
		},
		{
			name:    "fail/pkcs1v15",
			client:  &MockClient{},
			opts:    &rsa.PKCS1v15DecryptOptions{},
			wantErr: true,
		},
		{
			name: "fail/api-error-nil-opts",
			client: &MockClient{
				decrypt: func(req *km.DecryptRequest, _ ...scw.RequestOption) (*km.DecryptResponse, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			wantErr: true,
		},
		{
			name: "fail/decrypt-error",
			client: &MockClient{
				decrypt: func(req *km.DecryptRequest, _ ...scw.RequestOption) (*km.DecryptResponse, error) {
					return nil, fmt.Errorf("api error")
				},
			},
			opts:    &rsa.OAEPOptions{Hash: crypto.SHA256},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Decrypter{
				client:    tt.client,
				keyID:     testKeyID,
				region:    testRegion,
				publicKey: pk,
			}
			got, err := d.Decrypt(rand.Reader, []byte("ciphertext"), tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, plaintext, got)
		})
	}
}

// Compile-time assertion.
var _ crypto.Decrypter = (*Decrypter)(nil)
