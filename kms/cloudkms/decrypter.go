package cloudkms

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

// CreateDecrypter implements the apiv1.Decrypter interface and returns
// a crypto.Decrypter backed by a decryption key in Google Cloud KMS.
func (k *CloudKMS) CreateDecrypter(req *apiv1.CreateDecrypterRequest) (crypto.Decrypter, error) {
	if req.DecryptionKey == "" {
		return nil, errors.New("decryption key cannot be empty")
	}
	return NewDecrypter(k.client, req.DecryptionKey)
}

// Decrypter implements a crypto.Decrypter using Google Cloud KMS.
type Decrypter struct {
	client        KeyManagementClient
	decryptionKey string
	publicKey     crypto.PublicKey
}

// NewDecrypter creates a new crypto.Decrypter backed by the given
// Google Cloud KMS decryption key.
func NewDecrypter(client KeyManagementClient, decryptionKey string) (*Decrypter, error) {
	// Make sure that the key exists.
	decrypter := &Decrypter{
		client:        client,
		decryptionKey: decryptionKey,
	}
	if err := decrypter.preloadKey(decryptionKey); err != nil { // TODO(hs): (option for) lazy load instead?
		return nil, err
	}

	return decrypter, nil
}

func (d *Decrypter) preloadKey(signingKey string) error {
	ctx, cancel := defaultContext()
	defer cancel()

	response, err := d.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: signingKey,
	})
	if err != nil {
		return fmt.Errorf("cloudKMS GetPublicKey failed: %w", err)
	}

	d.publicKey, err = pemutil.ParseKey([]byte(response.Pem))
	return err
}

// Public returns the public key of this decrypter
func (d *Decrypter) Public() crypto.PublicKey {
	return d.publicKey
}

// validateOAEPOptions validates the RSA OAEP options provided.
func validateOAEPOptions(o *rsa.OAEPOptions) error {
	if o == nil { // var o *rsa.OAEPOptions; nothing to verify
		return nil
	}
	if len(o.Label) > 0 {
		return errors.New("cloudKMS does not support RSA-OAEP label")
	}
	switch o.Hash {
	case crypto.Hash(0), crypto.SHA1, crypto.SHA256, crypto.SHA512:
		return nil
	default:
		return fmt.Errorf("cloudKMS does not support hash algorithm %q with RSA-OAEP", o.Hash)
	}
}

// Decrypt decrypts ciphertext using the decryption key backed by Google Cloud KMS and returns
// the plaintext bytes. An error is returned when decryption fails. Google Cloud KMS only supports
// RSA keys with 2048, 3072 or 4096 bits and will always use OAEP. It supports SHA1, SHA256 and
// SHA512. Labels are not supported. Before calling out to GCP, some validation is performed
// so that known bad parameters are detected client-side and a more meaningful error is returned
// for those cases.
//
// Also see https://cloud.google.com/kms/docs/algorithms#asymmetric_encryption_algorithms.
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
		return nil, errors.New("cloudKMS does not support PKCS #1 v1.5 decryption")
	default:
		return nil, errors.New("invalid options for Decrypt")
	}

	req := &kmspb.AsymmetricDecryptRequest{
		Name:             d.decryptionKey,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(crc32c(ciphertext)),
	}

	ctx, cancel := defaultContext()
	defer cancel()

	response, err := d.client.AsymmetricDecrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("cloudKMS AsymmetricDecrypt failed: %w", err)
	}

	if !response.VerifiedCiphertextCrc32C {
		return nil, errors.New("cloudKMS AsymmetricDecrypt: request corrupted in-transit")
	}
	if crc32c(response.Plaintext) != response.PlaintextCrc32C.Value {
		return nil, errors.New("cloudKMS AsymmetricDecrypt: response corrupted in-transit")
	}

	return response.Plaintext, nil
}

func crc32c(data []byte) int64 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return int64(crc32.Checksum(data, t))
}

var _ apiv1.Decrypter = (*CloudKMS)(nil)
