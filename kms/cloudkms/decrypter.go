package cloudkms

import (
	"crypto"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// CreateDecrypter implements the apiv1.Decrypter interface and returns
// a crypto.Decrypter backed by Google Cloud KMS.
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

// NewDecrypter creates a new crypto.Decrypter the given CloudKMS decryption key.
func NewDecrypter(c KeyManagementClient, decryptionKey string) (*Decrypter, error) {
	// Make sure that the key exists.
	decrypter := &Decrypter{
		client:        c,
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

func (d *Decrypter) Decrypt(rand io.Reader, msg []byte, opts crypto.DecrypterOpts) (plaintext []byte, err error) {
	// TODO(hs): detect if the ciphertext matches the key type and abort if
	// some unsupported combination and/or operation is used?
	ciphertextCRC32C := crc32c(msg)
	req := &kmspb.AsymmetricDecryptRequest{
		Name:             d.decryptionKey,
		Ciphertext:       msg,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	ctx, cancel := defaultContext()
	defer cancel()

	response, err := d.client.AsymmetricDecrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("cloudKMS AsymmetricDecrypt failed: %w", err)
	}

	if !response.VerifiedCiphertextCrc32C {
		return nil, fmt.Errorf("cloudKMS AsymmetricDecrypt: request corrupted in-transit")
	}
	if int64(crc32c(response.Plaintext)) != response.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("cloudKMS AsymmetricDecrypt: response corrupted in-transit")
	}

	return response.Plaintext, nil
}

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

var _ apiv1.Decrypter = (*CloudKMS)(nil)
