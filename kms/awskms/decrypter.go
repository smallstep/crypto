package awskms

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

// CreateDecrypter implements the [apiv1.Decrypter] interface and returns
// a [crypto.Decrypter] backed by a decryption key in AWS KMS.
func (k *KMS) CreateDecrypter(req *apiv1.CreateDecrypterRequest) (crypto.Decrypter, error) {
	if req.DecryptionKey == "" {
		return nil, errors.New("decryption key cannot be empty")
	}

	return NewDecrypter(k.client, req.DecryptionKey)
}

// Decrypter implements a [crypto.Decrypter] using AWS KMS.
type Decrypter struct {
	client    KeyManagementClient
	keyID     string
	publicKey crypto.PublicKey
}

// NewDecrypter creates a new [crypto.Decrypter] backed by the given
// AWS KMS. decryption key.
func NewDecrypter(client KeyManagementClient, decryptionKey string) (*Decrypter, error) {
	keyID, err := parseKeyID(decryptionKey)
	if err != nil {
		return nil, err
	}

	decrypter := &Decrypter{
		client: client,
		keyID:  keyID,
	}
	if err := decrypter.preloadKey(); err != nil {
		return nil, err
	}

	return decrypter, nil
}

func (d *Decrypter) preloadKey() error {
	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := d.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: pointer(d.keyID),
	})
	if err != nil {
		return fmt.Errorf("awskms GetPublicKey failed: %w", err)
	}

	d.publicKey, err = pemutil.ParseDER(resp.PublicKey)
	return err
}

// Public returns the public key of this decrypter
func (d *Decrypter) Public() crypto.PublicKey {
	return d.publicKey
}

// Decrypt decrypts ciphertext using the decryption key backed by AWS KMS and returns
// the plaintext bytes. An error is returned when decryption fails. AWS KMS only supports
// RSA keys with 2048, 3072 or 4096 bits and will always use OAEP. It supports SHA1 and SHA256.
// Labels are not supported. Before calling out to AWS, some validation is performed
// so that known bad parameters are detected client-side and a more meaningful error is returned
// for those cases.
//
// Also see https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html#key-spec-rsa.
func (d *Decrypter) Decrypt(_ io.Reader, ciphertext []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	algorithm, err := determineDecryptionAlgorithm(d.publicKey, opts)
	if err != nil {
		return nil, fmt.Errorf("failed determining decryption algorithm: %w", err)
	}

	req := &kms.DecryptInput{
		KeyId:               pointer(d.keyID),
		CiphertextBlob:      ciphertext,
		EncryptionAlgorithm: algorithm,
	}

	ctx, cancel := defaultContext()
	defer cancel()

	response, err := d.client.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("awskms Decrypt failed: %w", err)
	}

	// TODO: additional validation?

	return response.Plaintext, nil
}

const (
	awsOaepSha1   = "RSAES_OAEP_SHA_1"
	awsOaepSha256 = "RSAES_OAEP_SHA_256"
)

func determineDecryptionAlgorithm(key crypto.PublicKey, opts crypto.DecrypterOpts) (types.EncryptionAlgorithmSpec, error) {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("awskms does not support key type %T", key)
	}

	if opts == nil {
		opts = &rsa.OAEPOptions{}
	}

	var rsaOpts *rsa.OAEPOptions
	switch o := opts.(type) {
	case *rsa.OAEPOptions:
		if err := validateOAEPOptions(o); err != nil {
			return "", err
		}
		rsaOpts = o
	case *rsa.PKCS1v15DecryptOptions:
		return "", errors.New("awskms does not support PKCS #1 v1.5 decryption")
	default:
		return "", fmt.Errorf("invalid decrypter options type %T", opts)
	}

	switch bitSize := pub.Size() * 8; bitSize {
	default:
		return "", fmt.Errorf("awskms does not support RSA public key size %d", bitSize)
	case 2048, 3072, 4096:
		switch rsaOpts.Hash {
		case crypto.SHA1:
			return awsOaepSha1, nil
		case crypto.SHA256:
			return awsOaepSha256, nil
		case crypto.Hash(0):
			// set a sane default hashing algorithm when it's not set. AWS KMS only supports
			// SHA1 and SHA256, so using SHA256 generally shouldn't result in a decryption
			// operation breaking, but it depends on the sending side whether or not this
			// is the correct value. If it's not provided through opts, then there's no other
			// way to determine which algorithm to use, though, so this is an optimistic attempt
			// at decryption.
			return awsOaepSha256, nil
		default:
			return "", fmt.Errorf("awskms does not support hash algorithm %q with RSA-OAEP", rsaOpts.Hash)
		}
	}
}

// validateOAEPOptions validates the RSA OAEP options provided.
func validateOAEPOptions(o *rsa.OAEPOptions) error {
	if len(o.Label) > 0 {
		return errors.New("awskms does not support RSA-OAEP label")
	}

	switch {
	case o.Hash != 0 && o.MGFHash == 0: // assumes same hash is being used for both
		break
	case o.Hash != 0 && o.MGFHash != 0 && o.Hash != o.MGFHash:
		return fmt.Errorf("awskms does not support using different algorithms for hashing %q and masking %q", o.Hash, o.MGFHash)
	}

	return nil
}

var _ apiv1.Decrypter = (*KMS)(nil)
