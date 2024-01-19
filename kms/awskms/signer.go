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
	alg, err := getSigningAlgorithm(s.Public(), opts)
	if err != nil {
		return nil, err
	}

	req := &kms.SignInput{
		KeyId:            pointer(s.keyID),
		SigningAlgorithm: alg,
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
	}

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := s.client.Sign(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "awskms Sign failed")
	}

	return resp.Signature, nil
}

func getSigningAlgorithm(key crypto.PublicKey, opts crypto.SignerOpts) (types.SigningAlgorithmSpec, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		_, isPSS := opts.(*rsa.PSSOptions)
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha256, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
		case crypto.SHA384:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha384, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
		case crypto.SHA512:
			if isPSS {
				return types.SigningAlgorithmSpecRsassaPssSha512, nil
			}
			return types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
		default:
			return "", errors.Errorf("unsupported hash function %v", h)
		}
	case *ecdsa.PublicKey:
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			return types.SigningAlgorithmSpecEcdsaSha256, nil
		case crypto.SHA384:
			return types.SigningAlgorithmSpecEcdsaSha384, nil
		case crypto.SHA512:
			return types.SigningAlgorithmSpecEcdsaSha512, nil
		default:
			return "", errors.Errorf("unsupported hash function %v", h)
		}
	default:
		return "", errors.Errorf("unsupported key type %T", key)
	}
}
