// Package mldsa provides a thin, version-independent bridge to the standard
// library's crypto/mldsa package (added in Go 1.27, implementing the ML-DSA
// post-quantum signature scheme specified in FIPS 204).
//
// On Go 1.27 and later the exported types are aliases for the standard library
// types, so keys produced by crypto/x509 (for example by ParsePKCS8PrivateKey)
// are the same concrete types used throughout go.step.sm/crypto. On older Go
// versions the package still compiles, but every operation returns
// [ErrUnsupported] instead. This lets the rest of the module—and its
// importers—reference ML-DSA unconditionally while keeping older toolchains
// building.
//
// The three parameter sets are identified by the canonical FIPS 204 names
// "ML-DSA-44", "ML-DSA-65" and "ML-DSA-87".
package mldsa

import (
	"crypto"
	"fmt"
	"strings"
)

// Parameter set names as defined in FIPS 204. These match the values returned
// by [Parameters.String].
const (
	MLDSA44Name = "ML-DSA-44"
	MLDSA65Name = "ML-DSA-65"
	MLDSA87Name = "ML-DSA-87"
)

// ParametersByName returns the [Parameters] for the given parameter set name.
// The name is matched case-insensitively against "ML-DSA-44", "ML-DSA-65" and
// "ML-DSA-87".
func ParametersByName(name string) (Parameters, error) {
	switch {
	case strings.EqualFold(name, MLDSA44Name):
		return MLDSA44(), nil
	case strings.EqualFold(name, MLDSA65Name):
		return MLDSA65(), nil
	case strings.EqualFold(name, MLDSA87Name):
		return MLDSA87(), nil
	default:
		return Parameters{}, fmt.Errorf("unrecognized ML-DSA parameter set %q", name)
	}
}

// GenerateSigner generates a new ML-DSA private key for the named parameter set
// and returns it as a [crypto.Signer]. It returns an error wrapping
// [ErrUnsupported] when built with a Go toolchain older than 1.27.
func GenerateSigner(name string) (crypto.Signer, error) {
	params, err := ParametersByName(name)
	if err != nil {
		return nil, err
	}
	sk, err := GenerateKey(params)
	if err != nil {
		return nil, err
	}
	return sk, nil
}
