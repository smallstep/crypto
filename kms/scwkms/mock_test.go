package scwkms

import (
	km "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

// MockClient implements KeyManagementClient for unit testing.
type MockClient struct {
	createKey    func(*km.CreateKeyRequest, ...scw.RequestOption) (*km.Key, error)
	getKey       func(*km.GetKeyRequest, ...scw.RequestOption) (*km.Key, error)
	getPublicKey func(*km.GetPublicKeyRequest, ...scw.RequestOption) (*km.PublicKey, error)
	sign         func(*km.SignRequest, ...scw.RequestOption) (*km.SignResponse, error)
	decrypt      func(*km.DecryptRequest, ...scw.RequestOption) (*km.DecryptResponse, error)
	deleteKey    func(*km.DeleteKeyRequest, ...scw.RequestOption) error
}

func (m *MockClient) CreateKey(req *km.CreateKeyRequest, opts ...scw.RequestOption) (*km.Key, error) {
	return m.createKey(req, opts...)
}

func (m *MockClient) GetKey(req *km.GetKeyRequest, opts ...scw.RequestOption) (*km.Key, error) {
	return m.getKey(req, opts...)
}

func (m *MockClient) GetPublicKey(req *km.GetPublicKeyRequest, opts ...scw.RequestOption) (*km.PublicKey, error) {
	return m.getPublicKey(req, opts...)
}

func (m *MockClient) Sign(req *km.SignRequest, opts ...scw.RequestOption) (*km.SignResponse, error) {
	return m.sign(req, opts...)
}

func (m *MockClient) Decrypt(req *km.DecryptRequest, opts ...scw.RequestOption) (*km.DecryptResponse, error) {
	return m.decrypt(req, opts...)
}

func (m *MockClient) DeleteKey(req *km.DeleteKeyRequest, opts ...scw.RequestOption) error {
	return m.deleteKey(req, opts...)
}
