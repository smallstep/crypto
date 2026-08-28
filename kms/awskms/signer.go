//go:build !noawskms

package awskms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/pkg/errors"

	"go.step.sm/crypto/mldsa"
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
		KeyId: new(keyID),
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

	var messageType types.MessageType
	switch alg {
	case types.SigningAlgorithmSpecEd25519Sha512:
		messageType = types.MessageTypeRaw
		// AWS does not support Ed25519 (ED25519_SHA_512) with messages larger than 4096 bytes
		if len(digest) > 4096 {
			return nil, fmt.Errorf("awskms Sign failed: message must have length less than or equal to 4096")
		}
	case types.SigningAlgorithmSpecMlDsaShake256:
		if len(digest) > 4096 {
			messageType = types.MessageTypeExternalMu
			digest, err = mldsaMessageHash(s.publicKey, digest, opts)
			if err != nil {
				return nil, fmt.Errorf("awskms Sign failed: %w", err)
			}
		} else {
			messageType = types.MessageTypeRaw
		}
	default:
		messageType = types.MessageTypeDigest
	}

	req := &kms.SignInput{
		KeyId:            new(s.keyID),
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
	case *mldsa.PublicKey:
		return types.SigningAlgorithmSpecMlDsaShake256, nil
	case ed25519.PublicKey:
		return types.SigningAlgorithmSpecEd25519Sha512, nil
	default:
		return "", errors.Errorf("unsupported key type %T", key)
	}
}

func mldsaMessageHash(pub crypto.PublicKey, msg []byte, o crypto.SignerOpts) ([]byte, error) {
	pk, ok := pub.(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T", pub)
	}

	opts, _ := o.(*mldsa.Options)
	h, err := mldsa.MessageHash(pk, msg, opts)
	if err != nil {
		return nil, err
	}
	return h[:], nil
}
