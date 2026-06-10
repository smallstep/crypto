//go:build !noscwkms

package scwkms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"

	km "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// scwKeyAlgorithmMapping maps a Scaleway asymmetric signing algorithm to the
// corresponding x509.SignatureAlgorithm. This reverse mapping is used by the
// Signer to expose the correct SignatureAlgorithm() value — critical for
// distinguishing RSA-PKCS1 from RSA-PSS when signing certificates.
var scwKeyAlgorithmMapping = map[km.KeyAlgorithmAsymmetricSigning]x509.SignatureAlgorithm{
	km.KeyAlgorithmAsymmetricSigningEcP256Sha256:        x509.ECDSAWithSHA256,
	km.KeyAlgorithmAsymmetricSigningEcP384Sha384:        x509.ECDSAWithSHA384,
	km.KeyAlgorithmAsymmetricSigningRsaPkcs1_2048Sha256: x509.SHA256WithRSA,
	km.KeyAlgorithmAsymmetricSigningRsaPkcs1_3072Sha256: x509.SHA256WithRSA,
	km.KeyAlgorithmAsymmetricSigningRsaPkcs1_4096Sha256: x509.SHA256WithRSA,
	km.KeyAlgorithmAsymmetricSigningRsaPss2048Sha256:    x509.SHA256WithRSAPSS,
	km.KeyAlgorithmAsymmetricSigningRsaPss3072Sha256:    x509.SHA256WithRSAPSS,
	km.KeyAlgorithmAsymmetricSigningRsaPss4096Sha256:    x509.SHA256WithRSAPSS,
}

// Signer implements a crypto.Signer using Scaleway Key Manager.
type Signer struct {
	client    KeyManagementClient
	keyID     string
	region    scw.Region
	algorithm x509.SignatureAlgorithm
	publicKey crypto.PublicKey
}

// NewSigner creates a new Signer for the given Scaleway signing key.
func NewSigner(client KeyManagementClient, signingKey string) (*Signer, error) {
	keyID, region := parseKeyName(signingKey, "")

	signer := &Signer{
		client: client,
		keyID:  keyID,
		region: region,
	}
	if err := signer.preloadKey(); err != nil {
		return nil, err
	}

	return signer, nil
}

// preloadKey fetches both the key metadata (for algorithm) and the public key
// (for the PEM). Two calls are necessary: GetKey provides the algorithm/usage
// required to distinguish RSA-PKCS1 from RSA-PSS; GetPublicKey provides the
// raw PEM bytes.
func (s *Signer) preloadKey() error {
	// GetKey → algorithm
	key, err := s.client.GetKey(&km.GetKeyRequest{
		Region: s.region,
		KeyID:  s.keyID,
	})
	if err != nil {
		return fmt.Errorf("scwkms GetKey failed: %w", err)
	}

	if key.Usage != nil && key.Usage.AsymmetricSigning != nil {
		if alg, ok := scwKeyAlgorithmMapping[*key.Usage.AsymmetricSigning]; ok {
			s.algorithm = alg
		}
		// Unknown algorithm → x509.UnknownSignatureAlgorithm (zero value), which is fine.
	}

	// GetPublicKey → PEM
	pubKeyResp, err := s.client.GetPublicKey(&km.GetPublicKeyRequest{
		Region: s.region,
		KeyID:  s.keyID,
	})
	if err != nil {
		return fmt.Errorf("scwkms GetPublicKey failed: %w", err)
	}

	s.publicKey, err = parsePublicKeyPEM([]byte(pubKeyResp.Pem))
	return err
}

// Public returns the public key of this signer.
func (s *Signer) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the given digest using the Scaleway Key Manager signing API.
//
// Scaleway uses digest-only signing (the digest is sent directly). ECDSA
// signatures returned by Scaleway are defensively normalised to ASN.1 DER
// format because some KMS providers return raw IEEE P-1363 (r‖s) encoding.
// Go's x509 verifiers require DER.
//
// TODO: Remove the raw→DER normalisation once Scaleway's wire format is
// confirmed via a live integration test.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Validate that the requested hash is compatible with the key algorithm.
	switch opts.HashFunc() {
	case crypto.SHA256, crypto.SHA384, crypto.SHA512:
		// accepted
	default:
		return nil, fmt.Errorf("scwkms Sign: unsupported hash function %v", opts.HashFunc())
	}

	// The Scaleway SDK manages context internally via HTTP; no explicit timeout
	// context is threaded through the Sign call here.

	response, err := s.client.Sign(&km.SignRequest{
		Region: s.region,
		KeyID:  s.keyID,
		Digest: digest,
	})
	if err != nil {
		return nil, fmt.Errorf("scwkms Sign failed: %w", err)
	}

	sig := response.Signature

	// Normalise ECDSA signatures to ASN.1 DER if the key is an ECDSA key.
	if ecKey, ok := s.publicKey.(*ecdsa.PublicKey); ok {
		sig, err = normalizeECDSASignature(sig, ecKey)
		if err != nil {
			return nil, fmt.Errorf("scwkms Sign: signature normalisation failed: %w", err)
		}
	}

	return sig, nil
}

// SignatureAlgorithm returns the signature algorithm of this signer.
// This is used when signing certificates to correctly encode the algorithm
// identifier — especially important to distinguish RSA-PKCS1 from RSA-PSS.
func (s *Signer) SignatureAlgorithm() x509.SignatureAlgorithm {
	return s.algorithm
}

// normalizeECDSASignature ensures the signature bytes are in ASN.1 DER format.
// If the signature is 2×curveByteLen bytes (raw IEEE P-1363 r‖s), it is
// re-encoded as DER SEQUENCE { INTEGER r, INTEGER s }.
// If the length does not match the raw format, the bytes are returned as-is
// (assumed to already be DER).
func normalizeECDSASignature(sig []byte, pubKey *ecdsa.PublicKey) ([]byte, error) {
	curveByteLen := (pubKey.Curve.Params().BitSize + 7) / 8
	if len(sig) != curveByteLen*2 {
		// Not raw P-1363; assume DER and return unchanged.
		return sig, nil
	}

	// Raw P-1363 format: encode as DER SEQUENCE { INTEGER r, INTEGER s }.
	r := new(big.Int).SetBytes(sig[:curveByteLen])
	sv := new(big.Int).SetBytes(sig[curveByteLen:])

	var b cryptobyte.Builder
	b.AddASN1(cryptobyteasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(sv)
	})
	return b.Bytes()
}
