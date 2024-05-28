package platform

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"go.step.sm/crypto/kms/apiv1"
)

// Scheme is the scheme used in uris, the string "kms".
const Scheme = string(apiv1.PlatformKMS)

func init() {
	apiv1.Register(apiv1.PlatformKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

type KMS struct {
	backend       platformKeyManager
	defaultSigAlg apiv1.SignatureAlgorithm
	defaultBits   int
}

type platformKeyManager interface {
	apiv1.KeyManager
	apiv1.CertificateChainManager
	DeleteKey(req *apiv1.DeleteKeyRequest) error
	DeleteCertificate(req *apiv1.DeleteCertificateRequest) error
}

// New returns a new PlatformKMS. This kms will use mackms on macOS, and tpmkms
// for linux and windows.
func New(ctx context.Context, o apiv1.Options) (*KMS, error) {
	return newKMS(ctx, o)
}

func (k *KMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("getPublicKeyRequest 'name' cannot be empty")
	}
	name, err := k.createURI(req.Name)
	if err != nil {
		return nil, err
	}
	return k.backend.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: name,
	})
}

func (k *KMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("createKeyRequest 'name' cannot empty")
	}
	name, err := k.createURI(req.Name)
	if err != nil {
		return nil, err
	}

	// With mackms we can create multiple keys with the same name but tpmkms
	// cannot. Checking the presence of the key makes sure that we don't create
	// a new key with the same name.
	if _, err := k.backend.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: name,
	}); err == nil {
		return nil, apiv1.AlreadyExistsError{}
	}

	return k.backend.CreateKey(&apiv1.CreateKeyRequest{
		Name:               name,
		SignatureAlgorithm: cmpOr(req.SignatureAlgorithm, k.defaultSigAlg),
		Bits:               cmpOr(req.Bits, k.defaultBits),
	})
}

func (k *KMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("deleteKeyRequest 'name' cannot be empty")
	}
	name, err := k.createURI(req.Name)
	if err != nil {
		return err
	}
	return k.backend.DeleteKey(&apiv1.DeleteKeyRequest{
		Name: name,
	})
}

func (k *KMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, fmt.Errorf("createSignerRequest 'signingKey' cannot be empty")
	}
	signingKey, err := k.createURI(req.SigningKey)
	if err != nil {
		return nil, err
	}
	return k.backend.CreateSigner(&apiv1.CreateSignerRequest{
		SigningKey: signingKey,
	})
}

func (k *KMS) CreateAttestation(*apiv1.CreateAttestationRequest) (*apiv1.CreateAttestationResponse, error) {
	return nil, apiv1.NotImplementedError{}
}

func (k *KMS) LoadCertificateChain(req *apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("loadCertificateChainRequest 'name' cannot be empty")
	}
	name, err := k.createURI(req.Name)
	if err != nil {
		return nil, err
	}
	return k.backend.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
		Name: name,
	})
}

func (k *KMS) StoreCertificateChain(req *apiv1.StoreCertificateChainRequest) error {
	switch {
	case req.Name == "":
		return errors.New("storeCertificateChainRequest 'name' cannot be empty")
	case len(req.CertificateChain) == 0:
		return errors.New("storeCertificateChainRequest 'certificateChain' cannot be empty")
	}
	name, err := k.createURI(req.Name)
	if err != nil {
		return err
	}
	return k.backend.StoreCertificateChain(&apiv1.StoreCertificateChainRequest{
		Name:             name,
		CertificateChain: req.CertificateChain,
	})
}

func (k *KMS) DeleteCertificate(req *apiv1.DeleteCertificateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("deleteCertificateRequest 'name' cannot be empty")
	}
	name, err := k.createURI(req.Name)
	if err != nil {
		return err
	}
	return k.backend.DeleteCertificate(&apiv1.DeleteCertificateRequest{
		Name: name,
	})
}

func (k *KMS) Close() error {
	return k.backend.Close()
}

// creates a kms specific uri. Supported parameters are:
//   - "name": string value representing a key, certificate, ... (required)
//   - "ak": boolean value representing in the key is an attestation key.
//   - "attest-by": string value representing the attestation key name.
//   - "qualifying-data": the data to be attested.
func (k *KMS) createURI(rawuri string) (string, error) {
	return createURI(rawuri)
}

// cmpOr returns the first of its arguments that is not equal to the zero value.
// If no argument is non-zero, it returns the zero value.
//
// This method is the same as cmp.Or, but that one was added on go1.22.0
func cmpOr[T comparable](vals ...T) T {
	var zero T
	for _, val := range vals {
		if val != zero {
			return val
		}
	}
	return zero
}
