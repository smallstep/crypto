//go:build !noscwkms

package scwkms

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	km "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"

	"go.step.sm/crypto/kms/apiv1"
)

// CreateDecrypter implements the apiv1.Decrypter interface and returns a
// crypto.Decrypter backed by a Scaleway asymmetric encryption key.
//
// Scaleway only supports RSA-OAEP-SHA256 for asymmetric decryption.
func (k *ScalewayKMS) CreateDecrypter(req *apiv1.CreateDecrypterRequest) (crypto.Decrypter, error) {
	if req.DecryptionKey == "" {
		return nil, errors.New("scwkms CreateDecrypter: 'decryptionKey' cannot be empty")
	}
	return NewDecrypter(k.client, req.DecryptionKey)
}

// Decrypter implements crypto.Decrypter using Scaleway Key Manager.
type Decrypter struct {
	client    KeyManagementClient
	keyID     string
	region    scw.Region
	publicKey crypto.PublicKey
}

// NewDecrypter creates a new crypto.Decrypter backed by the given Scaleway key.
func NewDecrypter(client KeyManagementClient, decryptionKey string) (*Decrypter, error) {
	keyID, region := parseKeyName(decryptionKey, "")

	decrypter := &Decrypter{
		client: client,
		keyID:  keyID,
		region: region,
	}
	if err := decrypter.preloadKey(); err != nil {
		return nil, err
	}

	return decrypter, nil
}

func (d *Decrypter) preloadKey() error {
	response, err := d.client.GetPublicKey(&km.GetPublicKeyRequest{
		Region: d.region,
		KeyID:  d.keyID,
	})
	if err != nil {
		return fmt.Errorf("scwkms GetPublicKey failed: %w", err)
	}

	d.publicKey, err = parsePublicKeyPEM([]byte(response.Pem))
	return err
}

// Public returns the public key of this decrypter.
func (d *Decrypter) Public() crypto.PublicKey {
	return d.publicKey
}

// validateOAEPOptions validates the RSA OAEP options provided.
// Scaleway only supports RSA-OAEP-SHA256; labels are not supported.
func validateOAEPOptions(o *rsa.OAEPOptions) error {
	if o == nil {
		return nil
	}
	if len(o.Label) > 0 {
		return errors.New("scwkms does not support RSA-OAEP label")
	}
	switch o.Hash {
	case crypto.Hash(0), crypto.SHA256:
		return nil
	default:
		return fmt.Errorf("scwkms does not support hash algorithm %q with RSA-OAEP (only SHA-256 is supported)", o.Hash)
	}
}

// Decrypt decrypts the given ciphertext using the Scaleway Key Manager
// asymmetric decryption API.
//
// Only RSA-OAEP-SHA256 is supported by Scaleway. Labels are not supported.
// The opts argument must be nil, a *rsa.OAEPOptions (with Hash 0 or SHA-256
// and no Label), or will produce an error.
func (d *Decrypter) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if opts == nil {
		opts = &rsa.OAEPOptions{}
	}
	switch o := opts.(type) {
	case *rsa.OAEPOptions:
		if err := validateOAEPOptions(o); err != nil {
			return nil, err
		}
	case *rsa.PKCS1v15DecryptOptions:
		return nil, errors.New("scwkms does not support PKCS#1 v1.5 decryption")
	default:
		return nil, errors.New("scwkms Decrypt: invalid options type")
	}

	response, err := d.client.Decrypt(&km.DecryptRequest{
		Region:     d.region,
		KeyID:      d.keyID,
		Ciphertext: ciphertext,
		// AssociatedData is nil: it is only used for symmetric AES-GCM keys,
		// not for RSA-OAEP asymmetric decryption.
	})
	if err != nil {
		return nil, fmt.Errorf("scwkms Decrypt failed: %w", err)
	}

	return response.Plaintext, nil
}

// Compile-time assertion.
var _ apiv1.Decrypter = (*ScalewayKMS)(nil)
