package platform

import (
	"context"
	"crypto"
	"crypto/x509"

	"go.step.sm/crypto/kms/apiv1"
)

const Scheme = "kms"

func init() {
	apiv1.Register(apiv1.PlatformKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
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
	backend extendedKeyManager
}

func New(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	return newKMS(ctx, opts)
}

func (k *KMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	return k.backend.GetPublicKey(req)
}

func (k *KMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	return k.backend.CreateKey(req)
}

func (k *KMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	return k.backend.CreateSigner(req)
}

func (k *KMS) Close() error {
	return k.backend.Close()
}

func (k *KMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	return k.backend.DeleteKey(req)
}

func (k *KMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	return k.backend.LoadCertificate(req)
}

func (k *KMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	return k.backend.StoreCertificate(req)
}

func (k *KMS) LoadCertificateChain(req *apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	return k.backend.LoadCertificateChain(req)
}

func (k *KMS) StoreCertificateChain(req *apiv1.StoreCertificateChainRequest) error {
	if km, ok := k.backend.(apiv1.CertificateChainManager); ok {
		return km.StoreCertificateChain(req)
	}

	return apiv1.NotImplementedError{}
}
