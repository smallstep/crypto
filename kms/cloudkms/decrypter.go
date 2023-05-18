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

// Decrypt decrypts ciphertext using the decryption key backed by Google Cloud KMS and returns
// the plaintext bytes. An error is returned when decryption fails. Google Cloud KMS only supports
// RSA keys with 2048, 3072 or 4096 bits and will always use OAEP. Labels are not supported.
//
// Also see https://cloud.google.com/kms/docs/algorithms#asymmetric_encryption_algorithms.
func (d *Decrypter) Decrypt(rand io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if ropts, ok := opts.(*rsa.OAEPOptions); ok && ropts != nil {
		if len(ropts.Label) > 0 {
			return nil, errors.New("cloudKMS does not support RSA-OAEP label")
		}
		switch ropts.Hash {
		case crypto.SHA1, crypto.SHA256, crypto.SHA512:
			break
		default:
			return nil, fmt.Errorf("cloudKMS does not support hash algorithm %q with RSA-OAEP", ropts.Hash)
		}
	}
	if _, ok := opts.(*rsa.PKCS1v15DecryptOptions); ok {
		return nil, errors.New("cloudKMS does not support PKCS #1 v1.5 decryption")
	}

	ciphertextCRC32C := crc32c(ciphertext)
	req := &kmspb.AsymmetricDecryptRequest{
		Name:             d.decryptionKey,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
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
	if int64(crc32c(response.Plaintext)) != response.PlaintextCrc32C.Value {
		return nil, errors.New("cloudKMS AsymmetricDecrypt: response corrupted in-transit")
	}

	return response.Plaintext, nil
}

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

var _ apiv1.Decrypter = (*CloudKMS)(nil)
