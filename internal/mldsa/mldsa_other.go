//go:build !go1.27

package mldsa

import (
	"crypto"
	"errors"
	"io"
)

var errNotSupported = errors.New("mldsa is not supported")

type PublicKey struct{}

type PrivateKey struct{}

func (sk *PrivateKey) Public() crypto.PublicKey {
	return nil
}

func (sk *PrivateKey) Sign(_ io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, errNotSupported
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

func GenerateKey(params Parameters) (*PrivateKey, error) {
	return nil, errNotSupported
}
