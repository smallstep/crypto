//go:build cgo && !nopkcs11
// +build cgo,!nopkcs11

package tpmkms

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/storage"
)

func init() {
	apiv1.Register(apiv1.TPMKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// Scheme is the scheme used in uris.
const Scheme = "tpmkms"

// TPMKMS is the implementation of a KMS backed by a TPM
type TPMKMS struct {
	tpm    *tpm.TPM
	closed sync.Once
}

// TODO: implement the other interfaces too? Decrypter could work, but haven't tested that
// yet. CertificateManager is probably nice, if we can store certs with the keys too. Namevalidator
// might be useful too, if we have a good URI scheme. Attester makes sense for the TPM, so definitely
// need to look into making that work.

// type Decrypter interface {
// 	CreateDecrypter(req *CreateDecrypterRequest) (crypto.Decrypter, error)
// }

// type CertificateManager interface {
// 	LoadCertificate(req *LoadCertificateRequest) (*x509.Certificate, error)
// 	StoreCertificate(req *StoreCertificateRequest) error
// }

// type NameValidator interface {
// 	ValidateName(s string) error
// }

// type Attester interface {
// 	CreateAttestation(req *CreateAttestationRequest) (*CreateAttestationResponse, error)
// }

// New returns a new TPM KMS.
func New(ctx context.Context, opts apiv1.Options) (*TPMKMS, error) {
	tpm, err := tpm.New(tpm.WithStore(storage.BlackHole())) // TODO: different type, based on config
	if err != nil {
		return nil, fmt.Errorf("failed creating new TPM: %w", err)
	}
	return &TPMKMS{
		tpm: tpm,
	}, nil
}

// CreateKey generates a new key in the PKCS#11 module and returns the public key.
func (k *TPMKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	// TODO: get (more) options from request
	name := req.Name
	bits := req.Bits

	config := tpm.CreateKeyConfig{
		Algorithm: "RSA", // TODO: make configurable
		Size:      bits,
	}
	key, err := k.tpm.CreateKey(context.TODO(), name, config)
	if err != nil {
		return nil, fmt.Errorf("failing creating key: %w", err)
	}

	signer, err := key.Signer(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failing getting signer for key: %w", err)
	}

	priv, ok := signer.(crypto.PrivateKey) // TODO: works as expected?
	if !ok {
		return nil, errors.New("failing getting private key")
	}

	return &apiv1.CreateKeyResponse{
		Name:       key.Name(),
		PublicKey:  signer.Public(),
		PrivateKey: priv,
		// CreateSignerRequest: apiv1.CreateSignerRequest{}, // TODO: required?
	}, nil
}

// CreateSigner creates a signer using a key present in the TPM module.
func (k *TPMKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {

	// TODO: use SigningKey instead?

	if req.Signer == nil {
		return nil, errors.New("no signer")
	}

	return req.Signer, nil // TODO: don't think this'll work as expected?
}

// GetPublicKey returns the public key ....
func (k *TPMKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, errors.New("getPublicKeyRequest 'name' cannot be empty")
	}

	// signer, err := findSigner(k.p11, req.Name)
	// if err != nil {
	// 	return nil, errors.Wrap(err, "getPublicKey failed")
	// }

	name := req.Name
	key, err := k.tpm.GetKey(context.TODO(), name)
	if err != nil {
		return nil, fmt.Errorf("failed getting key: %w", err)
	}

	signer, err := key.Signer(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed getting signer: %w", err)
	}

	return signer.Public(), nil
}

// Close releases the connection to the TPM.
func (k *TPMKMS) Close() (err error) {
	k.closed.Do(func() {
		// TODO: close active/open TPMs
		//err = errors.Wrap(k.p11.Close(), "error closing pkcs#11 context")
	})
	return
}
