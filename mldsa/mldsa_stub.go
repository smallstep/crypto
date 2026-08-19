//go:build !go1.27

package mldsa

import (
	"crypto"
	"errors"
	"io"
)

// Supported reports whether ML-DSA is available in the current build. It is
// false when compiled with a Go toolchain older than 1.27.
const Supported = false

// ErrUnsupported is returned by every ML-DSA operation when built with a Go
// toolchain older than 1.27.
var ErrUnsupported = errors.New("go.step.sm/crypto/mldsa: ML-DSA requires Go 1.27 or later")

// Parameters represents one of the ML-DSA parameter sets defined in FIPS 204.
// On Go versions older than 1.27 it only carries the parameter set name.
type Parameters struct {
	name string
}

// String returns the name of the parameter set, e.g. "ML-DSA-44".
func (p Parameters) String() string { return p.name }

// MLDSA44 returns the ML-DSA-44 parameter set defined in FIPS 204.
func MLDSA44() Parameters { return Parameters{name: MLDSA44Name} }

// MLDSA65 returns the ML-DSA-65 parameter set defined in FIPS 204.
func MLDSA65() Parameters { return Parameters{name: MLDSA65Name} }

// MLDSA87 returns the ML-DSA-87 parameter set defined in FIPS 204.
func MLDSA87() Parameters { return Parameters{name: MLDSA87Name} }

// PublicKey is a placeholder ML-DSA public key. On Go versions older than 1.27
// it is never populated; it exists so that type switches referencing ML-DSA
// keys compile.
type PublicKey struct{}

// Bytes always returns nil on unsupported builds.
func (*PublicKey) Bytes() []byte { return nil }

// Equal always returns false on unsupported builds.
func (*PublicKey) Equal(crypto.PublicKey) bool { return false }

// Parameters returns the zero Parameters on unsupported builds.
func (*PublicKey) Parameters() Parameters { return Parameters{} }

// PrivateKey is a placeholder ML-DSA private key. On Go versions older than 1.27
// it is never populated; it exists so that type switches referencing ML-DSA
// keys compile. It implements [crypto.Signer].
type PrivateKey struct{}

// Public returns nil on unsupported builds.
func (*PrivateKey) Public() crypto.PublicKey { return nil }

// Equal always returns false on unsupported builds.
func (*PrivateKey) Equal(crypto.PrivateKey) bool { return false }

// Bytes always returns nil on unsupported builds.
func (*PrivateKey) Bytes() []byte { return nil }

// Sign always returns ErrUnsupported on unsupported builds.
func (*PrivateKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, ErrUnsupported
}

// Options contains additional options for signing and verifying signatures.
type Options struct {
	// Context can be used to distinguish signatures created for different
	// purposes. It must be at most 255 bytes long, and it is empty by default.
	Context string
}

// HashFunc returns zero, to implement the [crypto.SignerOpts] interface.
func (*Options) HashFunc() crypto.Hash { return 0 }

// GenerateKey returns ErrUnsupported on unsupported builds.
func GenerateKey(Parameters) (*PrivateKey, error) { return nil, ErrUnsupported }

// NewPrivateKey returns ErrUnsupported on unsupported builds.
func NewPrivateKey(Parameters, []byte) (*PrivateKey, error) { return nil, ErrUnsupported }

// NewPublicKey returns ErrUnsupported on unsupported builds.
func NewPublicKey(Parameters, []byte) (*PublicKey, error) { return nil, ErrUnsupported }

// Verify returns ErrUnsupported on unsupported builds.
func Verify(*PublicKey, []byte, []byte, *Options) error { return ErrUnsupported }
