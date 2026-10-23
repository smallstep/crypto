// Package cryptoutil implements helpers for the crypto package.
package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
)

// SignerOpts returns the digest and options a signer must use to sign digest
// with key. If opts is not nil, it returns digest and opts unchanged.
//
// Callers that don't know which hash computed the digest, such as PKCS #11's
// CKM_ECDSA, pass nil opts. For ECDSA keys, SignerOpts then behaves like
// ecdsa.PrivateKey.Sign with nil opts: the hash is named by the curve, and a
// digest of any length is left-padded with zeros or truncated to the size of
// that hash, which gives the same signature as ECDSA would with the original
// digest. The exception is P-521 with a digest longer than 64 bytes: ECDSA
// uses up to its leftmost 521 bits, which don't fit in a SHA-512 digest, so
// it fails. An empty digest fails, as it does in crypto/ecdsa.
//
// RSA keys fail, as their signature depends on the hash. Other keys sign as
// with crypto.Hash(0).
func SignerOpts(key crypto.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, crypto.SignerOpts, error) {
	if opts != nil {
		return digest, opts, nil
	}

	switch k := key.(type) {
	case *ecdsa.PublicKey:
		var h crypto.Hash
		switch k.Curve {
		case elliptic.P256():
			h = crypto.SHA256
		case elliptic.P384():
			h = crypto.SHA384
		case elliptic.P521():
			h = crypto.SHA512
		case nil:
			return nil, nil, errors.New("ecdsa key has no curve")
		default:
			return nil, nil, fmt.Errorf("unsupported curve %s", k.Curve.Params().Name)
		}
		size := h.Size()
		switch n := len(digest); {
		case n == 0:
			// Matches ecdsa.PrivateKey.Sign, which rejects an empty digest.
			return nil, nil, errors.New("digest cannot be empty")
		case n == size:
			return digest, h, nil
		case n < size:
			padded := make([]byte, size)
			copy(padded[size-n:], digest)
			return padded, h, nil
		case k.Curve == elliptic.P521():
			// ECDSA would use up to the leftmost 521 bits of the digest,
			// which don't fit in the 512 bits of a SHA-512 digest.
			return nil, nil, fmt.Errorf("unsupported digest length %d for P-521, the maximum is %d", n, size)
		default:
			// ECDSA uses only the leftmost bits of the digest, as many as the
			// curve has, and P-256 and P-384 have as many as their hashes.
			return digest[:size], h, nil
		}
	case *rsa.PublicKey:
		return nil, nil, errors.New("rsa keys require signer options")
	default:
		return digest, crypto.Hash(0), nil
	}
}
