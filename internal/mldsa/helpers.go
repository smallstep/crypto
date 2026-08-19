package mldsa

import (
	"crypto/sha3"
	"errors"
)

var (
	errContextTooLong = errors.New("mldsa: context too long")
)

func PublicKeyHash(pub *PublicKey) [64]byte {
	H := sha3.NewSHAKE256()
	H.Write(pub.Bytes())
	var tr [64]byte
	H.Read(tr[:])
	return tr
}

func MessageHash(pub *PublicKey, msg []byte, opts *Options) ([64]byte, error) {
	if opts == nil {
		opts = &Options{}
	}

	tr := PublicKeyHash(pub)
	if len(opts.Context) > 255 {
		return [64]byte{}, errContextTooLong
	}

	H := sha3.NewSHAKE256()
	H.Write(tr[:])
	H.Write([]byte{0}) // ML-DSA / HashML-DSA domain separator
	H.Write([]byte{byte(len(opts.Context))})
	H.Write([]byte(opts.Context))
	H.Write(msg)
	var μ [64]byte
	H.Read(μ[:])
	return μ, nil
}
