//go:build go1.27

package mldsa

import (
	stdmldsa "crypto/mldsa"
)

// Supported reports whether ML-DSA is available in the current build. It is
// true when compiled with Go 1.27 or later.
const Supported = true

// These types are aliases for the standard library crypto/mldsa types, so keys
// returned by crypto/x509 and crypto/mldsa are interchangeable with the ones
// used throughout go.step.sm/crypto.
type (
	// PublicKey is an ML-DSA public key.
	PublicKey = stdmldsa.PublicKey
	// PrivateKey is an ML-DSA private key. It implements [crypto.Signer].
	PrivateKey = stdmldsa.PrivateKey
	// Parameters represents one of the ML-DSA parameter sets defined in FIPS 204.
	Parameters = stdmldsa.Parameters
	// Options contains additional options for signing and verifying signatures.
	Options = stdmldsa.Options
)

// Signature and key sizes for each parameter set, re-exported from the standard
// library for convenience.
const (
	PrivateKeySize       = stdmldsa.PrivateKeySize
	MLDSA44PublicKeySize = stdmldsa.MLDSA44PublicKeySize
	MLDSA65PublicKeySize = stdmldsa.MLDSA65PublicKeySize
	MLDSA87PublicKeySize = stdmldsa.MLDSA87PublicKeySize
	MLDSA44SignatureSize = stdmldsa.MLDSA44SignatureSize
	MLDSA65SignatureSize = stdmldsa.MLDSA65SignatureSize
	MLDSA87SignatureSize = stdmldsa.MLDSA87SignatureSize
)

// MLDSA44 returns the ML-DSA-44 parameter set defined in FIPS 204.
func MLDSA44() Parameters { return stdmldsa.MLDSA44() }

// MLDSA65 returns the ML-DSA-65 parameter set defined in FIPS 204.
func MLDSA65() Parameters { return stdmldsa.MLDSA65() }

// MLDSA87 returns the ML-DSA-87 parameter set defined in FIPS 204.
func MLDSA87() Parameters { return stdmldsa.MLDSA87() }

// GenerateKey generates a new random ML-DSA private key for the given parameter
// set.
func GenerateKey(params Parameters) (*PrivateKey, error) {
	return stdmldsa.GenerateKey(params)
}

// NewPrivateKey expands the given 32-byte seed into an ML-DSA private key for
// the given parameter set.
func NewPrivateKey(params Parameters, seed []byte) (*PrivateKey, error) {
	return stdmldsa.NewPrivateKey(params, seed)
}

// NewPublicKey decodes the given public key encoding for the given parameter
// set.
func NewPublicKey(params Parameters, encoding []byte) (*PublicKey, error) {
	return stdmldsa.NewPublicKey(params, encoding)
}

// Verify verifies the signature of message using the given public key and
// options.
func Verify(pk *PublicKey, message, signature []byte, opts *Options) error {
	return stdmldsa.Verify(pk, message, signature, opts)
}
