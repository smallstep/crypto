//go:build !go1.27

package mldsa

import (
	"crypto"
	"errors"
	"io"
)

var errNotSupported = errors.New("mldsa is not supported")

// Enabled returns if mdlsa package is implemented. It will return true in Go
// 1.27+ and false on lower versions.
func Enabled() bool {
	return false
}

type Parameters struct{}

func MLDSA44() Parameters {
	return Parameters{}
}

func MLDSA65() Parameters {
	return Parameters{}
}

func MLDSA87() Parameters {
	return Parameters{}
}

type Options struct {
	Context string
}

func (o *Options) HashFunc() crypto.Hash {
	return 0
}

type PrivateKey struct{}

func (sk *PrivateKey) Bytes() []byte {
	return nil
}

func (sk *PrivateKey) Equal(x crypto.PrivateKey) bool {
	return false
}

func (sk *PrivateKey) Public() crypto.PublicKey {
	return (*PublicKey)(nil)
}

func (sk *PrivateKey) PublicKey() *PublicKey {
	return (*PublicKey)(nil)
}

func (sk *PrivateKey) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, errNotSupported
}

type PublicKey struct{}

func (pk *PublicKey) Bytes() []byte {
	return nil
}

func (pk *PublicKey) Equal(x crypto.PublicKey) bool {
	return false
}

func (pk *PublicKey) Parameters() Parameters {
	return Parameters{}
}

func GenerateKey(params Parameters) (*PrivateKey, error) {
	return nil, errNotSupported
}

func Verify(pk *PublicKey, message, signature []byte, opts *Options) error {
	return errNotSupported
}
