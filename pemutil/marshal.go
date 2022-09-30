package pemutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/pkg/errors"
)

var oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

// MarshalPKIXPublicKey serializes a public key to DER-encoded PKIX format. The
// following key types are supported: *rsa.PublicKey, *ecdsa.PublicKey,
// ed25519.Publickey. Unsupported key types result in an error.
func MarshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error) {
	switch p := pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		return x509.MarshalPKIXPublicKey(pub)
	case ed25519.PublicKey:
		var pki publicKeyInfo
		pki.Algo.Algorithm = oidEd25519
		pki.PublicKey = asn1.BitString{
			Bytes:     p,
			BitLength: 8 * len(p),
		}
		return asn1.Marshal(pki)
	default:
		return nil, fmt.Errorf("unknown public key type: %T", pub)
	}
}

// MarshalPKCS8PrivateKey converts a private key to PKCS#8 encoded form. The
// following key types are supported: *rsa.PrivateKey, *ecdsa.PublicKey,
// ed25519.PrivateKey. Unsupported key types result in an error.
func MarshalPKCS8PrivateKey(key crypto.PrivateKey) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(key)
		return b, errors.Wrap(err, "error marshaling PKCS#8")
	case ed25519.PrivateKey:
		var priv pkcs8
		priv.PrivateKey = append([]byte{4, 32}, k.Seed()...)[:34]
		priv.Algo = pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112},
		}
		b, err := asn1.Marshal(priv)
		return b, errors.Wrap(err, "error marshaling PKCS#8")
	default:
		return nil, errors.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
	}
}
