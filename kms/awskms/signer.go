//go:build !noawskms
// +build !noawskms

package awskms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/pkg/errors"
	"go.step.sm/crypto/pemutil"
)

// AWSOptions implements the crypto.SignerOpts interface, it provides a Raw
// boolean field to indicate to the AWS KMS operation that the MessageType is
// RAW.
//
// Example:
//
//	 // Sign a raw message with KMS
//	 client := kms.NewFromConfig(cfg)
//	 kmsSigner, err := awskms.NewSigner(client, "my-key-id")
//	 if err != nil {
//		// handle error ...
//	 }
//	 raw := []byte("my raw message")
//	 sig, err := kmsSigner.Sign(rand.Reader, raw, &awskms.AWSOptions{
//		Raw: true,
//		Options: crypto.SHA256,
//	 })
//	 if err != nil {
//		// handle error ...
//	 }
type AWSOptions struct {
	// Raw specifies to the AWS KMS operation that MessageType is RAW.
	Raw     bool
	Options crypto.SignerOpts
}

// HashFunc implements crypto.SignerOpts.
func (a *AWSOptions) HashFunc() crypto.Hash {
	// The GoLang [crypto.SignerOpt] interfaces states that if the [HashFunc]
	// returns 0, then it indicates to the [Sign] function that no hashing
	// has occurred over the message.
	// However, the AWS KMS Sign operation always requires that a
	// SigningAlgorithm is specified.
	// As such, the AWSOptions HashFunc() must return a valid (non-zero) Hash,
	// such that the [getMessageTypeAndSigningAlgorithm] function can return a valid AWS KMS
	// [types.SigningAlgorithmSpec]
	return a.Options.HashFunc()
}

// compile time check that AWSOptions implements crypto.SignerOpts
var _ crypto.SignerOpts = (*AWSOptions)(nil)

// Signer implements a crypto.Signer using the AWS KMS.
type Signer struct {
	client    KeyManagementClient
	keyID     string
	publicKey crypto.PublicKey
}

// NewSigner creates a new signer using a key in the AWS KMS.
func NewSigner(client KeyManagementClient, signingKey string) (*Signer, error) {
	keyID, err := parseKeyID(signingKey)
	if err != nil {
		return nil, err
	}

	// Make sure that the key exists.
	signer := &Signer{
		client: client,
		keyID:  keyID,
	}
	if err := signer.preloadKey(keyID); err != nil {
		return nil, err
	}

	return signer, nil
}

func (s *Signer) preloadKey(keyID string) error {
	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := s.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: pointer(keyID),
	})
	if err != nil {
		return errors.Wrap(err, "awskms GetPublicKey failed")
	}

	s.publicKey, err = pemutil.ParseDER(resp.PublicKey)
	return err
}

// Public returns the public key of this signer or an error.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the private key stored in the AWS KMS.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	messageType, alg, err := getMessageTypeAndSigningAlgorithm(s.Public(), opts)
	if err != nil {
		return nil, err
	}

	req := &kms.SignInput{
		KeyId:            pointer(s.keyID),
		SigningAlgorithm: alg,
		Message:          digest,
		MessageType:      messageType,
	}

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := s.client.Sign(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "awskms Sign failed")
	}

	return resp.Signature, nil
}

func getMessageTypeAndSigningAlgorithm(key crypto.PublicKey, opts crypto.SignerOpts) (types.MessageType, types.SigningAlgorithmSpec, error) {
	messageType := types.MessageTypeDigest
	if awsOpts, ok := opts.(*AWSOptions); ok {
		if awsOpts.Raw {
			messageType = types.MessageTypeRaw
		}
		opts = awsOpts.Options
	}

	switch key.(type) {
	case *rsa.PublicKey:
		_, isPSS := opts.(*rsa.PSSOptions)
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			if isPSS {
				return messageType, types.SigningAlgorithmSpecRsassaPssSha256, nil
			}
			return messageType, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			if isPSS {
				return messageType, types.SigningAlgorithmSpecRsassaPssSha384, nil
			}
			return messageType, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			if isPSS {
				return messageType, types.SigningAlgorithmSpecRsassaPssSha512, nil
			}
			return messageType, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		default:
			return messageType, "", errors.Errorf("unsupported hash function %v", h)
		}
	case *ecdsa.PublicKey:
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			return messageType, types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return messageType, types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return messageType, types.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return messageType, "", errors.Errorf("unsupported hash function %v", h)
		}
	default:
		return messageType, "", errors.Errorf("unsupported key type %T", key)
	}
}
