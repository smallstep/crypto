//go:build !noazurekms
// +build !noazurekms

package azurekms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"io"
	"math/big"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/pkg/errors"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

// Signer implements a crypto.Signer using the AWS KMS.
type Signer struct {
	client    KeyVaultClient
	name      string
	version   string
	publicKey crypto.PublicKey
}

// NewSigner creates a new signer using a key in the AWS KMS.
func NewSigner(lazyClient *lazyClient, signingKey string, defaults defaultOptions) (crypto.Signer, error) {
	vaultURL, name, version, _, err := parseKeyName(signingKey, defaults)
	if err != nil {
		return nil, err
	}

	client, err := lazyClient.Get(vaultURL)
	if err != nil {
		return nil, err
	}

	// Make sure that the key exists.
	signer := &Signer{
		client:  client,
		name:    name,
		version: version,
	}
	if err := signer.preloadKey(); err != nil {
		return nil, err
	}

	return signer, nil
}

func (s *Signer) preloadKey() error {
	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := s.client.GetKey(ctx, s.name, s.version, nil)
	if err != nil {
		return errors.Wrap(err, "keyVault GetKey failed")
	}

	s.publicKey, err = convertKey(resp.Key)
	return err
}

// Public returns the public key of this signer or an error.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs digest with the private key stored in the Azure Key Vault.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	alg, err := getSigningAlgorithm(s.Public(), opts)
	if err != nil {
		return nil, err
	}

	// Sign with retry if the key is not ready
	resp, err := s.signWithRetry(alg, digest, 3)
	if err != nil {
		return nil, errors.Wrap(err, "keyVault Sign failed")
	}

	var octetSize int
	switch alg {
	case azkeys.JSONWebKeySignatureAlgorithmES256:
		octetSize = 32 // 256-bit, concat(R,S) = 64 bytes
	case azkeys.JSONWebKeySignatureAlgorithmES384:
		octetSize = 48 // 384-bit, concat(R,S) = 96 bytes
	case azkeys.JSONWebKeySignatureAlgorithmES512:
		octetSize = 66 // 528-bit, concat(R,S) = 132 bytes
	default:
		return resp.Result, nil
	}

	// Convert to asn1
	if len(resp.Result) != octetSize*2 {
		return nil, errors.Errorf("keyVault Sign failed: unexpected signature length")
	}
	var b cryptobyte.Builder
	b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(new(big.Int).SetBytes(resp.Result[:octetSize])) // R
		b.AddASN1BigInt(new(big.Int).SetBytes(resp.Result[octetSize:])) // S
	})
	return b.Bytes()
}

func (s *Signer) signWithRetry(alg azkeys.JSONWebKeySignatureAlgorithm, digest []byte, retryAttempts int) (azkeys.SignResponse, error) {
retry:
	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := s.client.Sign(ctx, s.name, s.version, azkeys.SignParameters{
		Algorithm: &alg,
		Value:     digest,
	}, nil)
	if err != nil && retryAttempts > 0 {
		var responseError *azcore.ResponseError
		if errors.As(err, &responseError) {
			if responseError.StatusCode == 429 {
				time.Sleep(time.Second / time.Duration(retryAttempts))
				retryAttempts--
				goto retry
			}
		}
	}
	return resp, err
}

func getSigningAlgorithm(key crypto.PublicKey, opts crypto.SignerOpts) (azkeys.JSONWebKeySignatureAlgorithm, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		hashFunc := opts.HashFunc()
		pss, isPSS := opts.(*rsa.PSSOptions)
		// Random salt lengths are not supported
		if isPSS &&
			pss.SaltLength != rsa.PSSSaltLengthAuto &&
			pss.SaltLength != rsa.PSSSaltLengthEqualsHash &&
			pss.SaltLength != hashFunc.Size() {
			return "", errors.Errorf("unsupported RSA-PSS salt length %d", pss.SaltLength)
		}

		switch h := hashFunc; h {
		case crypto.SHA256:
			if isPSS {
				return azkeys.JSONWebKeySignatureAlgorithmPS256, nil
			}
			return azkeys.JSONWebKeySignatureAlgorithmRS256, nil
		case crypto.SHA384:
			if isPSS {
				return azkeys.JSONWebKeySignatureAlgorithmPS384, nil
			}
			return azkeys.JSONWebKeySignatureAlgorithmRS384, nil
		case crypto.SHA512:
			if isPSS {
				return azkeys.JSONWebKeySignatureAlgorithmPS512, nil
			}
			return azkeys.JSONWebKeySignatureAlgorithmRS512, nil
		default:
			return "", errors.Errorf("unsupported hash function %v", h)
		}
	case *ecdsa.PublicKey:
		switch h := opts.HashFunc(); h {
		case crypto.SHA256:
			return azkeys.JSONWebKeySignatureAlgorithmES256, nil
		case crypto.SHA384:
			return azkeys.JSONWebKeySignatureAlgorithmES384, nil
		case crypto.SHA512:
			return azkeys.JSONWebKeySignatureAlgorithmES512, nil
		default:
			return "", errors.Errorf("unsupported hash function %v", h)
		}
	default:
		return "", errors.Errorf("unsupported key type %T", key)
	}
}
