package platform

import (
	"context"
	"crypto"
	"crypto/x509"
	"net/url"
	"strings"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
)

const Scheme = "kms"

func init() {
	apiv1.Register(apiv1.PlatformKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

const (
	backendKey = "backend"
	nameKey    = "name"
	hwKey      = "hw"
)

type kmsURI struct {
	uri         *uri.URI
	backend     apiv1.Type
	name        string
	hw          bool
	extraValues url.Values
}

func parseURI(rawuri string) (*kmsURI, error) {
	u, err := uri.ParseWithScheme(Scheme, rawuri)
	if err != nil {
		return nil, err
	}

	extraValues := make(url.Values)
	for k, v := range u.Values {
		if k != nameKey && k != hwKey && k != backendKey {
			extraValues[k] = v
		}
	}

	return &kmsURI{
		uri:         u,
		backend:     apiv1.Type(strings.ToLower(u.Get(backendKey))),
		name:        u.Get(nameKey),
		hw:          u.GetBool(hwKey),
		extraValues: extraValues,
	}, nil
}

type extendedKeyManager interface {
	apiv1.KeyManager
	apiv1.KeyDeleter
	apiv1.CertificateManager
	apiv1.CertificateChainManager
}

var _ apiv1.KeyManager = (*KMS)(nil)
var _ apiv1.CertificateManager = (*KMS)(nil)
var _ apiv1.CertificateChainManager = (*KMS)(nil)

type KMS struct {
	backend      extendedKeyManager
	transformURI func(*kmsURI) string
}

func New(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	return newKMS(ctx, opts)
}

func (k *KMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	name, err := k.transform(req.Name)
	if err != nil {
		return nil, err
	}
	return k.backend.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: name,
	})
}

func (k *KMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	name, err := k.transform(req.Name)
	if err != nil {
		return nil, err
	}

	req = clone(req)
	req.Name = name
	return k.backend.CreateKey(req)
}

func (k *KMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	signingKey, err := k.transform(req.SigningKey)
	if err != nil {
		return nil, err
	}

	req = clone(req)
	req.SigningKey = signingKey
	return k.backend.CreateSigner(req)
}

func (k *KMS) Close() error {
	return k.backend.Close()
}

func (k *KMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	name, err := k.transform(req.Name)
	if err != nil {
		return err
	}

	req = clone(req)
	req.Name = name
	return k.backend.DeleteKey(req)
}

func (k *KMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	name, err := k.transform(req.Name)
	if err != nil {
		return nil, err
	}

	req = clone(req)
	req.Name = name
	return k.backend.LoadCertificate(req)
}

func (k *KMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	name, err := k.transform(req.Name)
	if err != nil {
		return err
	}

	req = clone(req)
	req.Name = name
	return k.backend.StoreCertificate(req)
}

func (k *KMS) LoadCertificateChain(req *apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	name, err := k.transform(req.Name)
	if err != nil {
		return nil, err
	}

	req = clone(req)
	req.Name = name
	return k.backend.LoadCertificateChain(req)
}

func (k *KMS) StoreCertificateChain(req *apiv1.StoreCertificateChainRequest) error {
	name, err := k.transform(req.Name)
	if err != nil {
		return err
	}

	req = clone(req)
	req.Name = name
	return k.backend.StoreCertificateChain(req)
}

func (k *KMS) SearchKeys(req *apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error) {
	if km, ok := k.backend.(apiv1.SearchableKeyManager); ok {
		query, err := k.transform(req.Query)
		if err != nil {
			return nil, err
		}

		req = clone(req)
		req.Query = query
		return km.SearchKeys(req)
	}

	return nil, apiv1.NotImplementedError{}
}

func (k *KMS) transform(rawuri string) (string, error) {
	u, err := parseURI(rawuri)
	if err != nil {
		return "", err
	}

	return k.transformURI(u), nil
}

func clone[T any](v *T) *T {
	c := *v
	return &c
}
