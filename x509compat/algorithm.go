package x509compat

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
)

// PublicKeyAlgorithm represents a public key algorithm.
//
// In Agiligo, these are replaced by the crypto.PublicKeyAlgorithm interface
// and dynamic registration. This type exists for backward compatibility with
// code that uses x509.PublicKeyAlgorithm constants.
type PublicKeyAlgorithm int

const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	DSA // Deprecated: DSA is not secure
	ECDSA
	Ed25519
)

// String returns the name of the algorithm.
func (algo PublicKeyAlgorithm) String() string {
	switch algo {
	case RSA:
		return "RSA"
	case DSA:
		return "DSA"
	case ECDSA:
		return "ECDSA"
	case Ed25519:
		return "Ed25519"
	default:
		return "unknown public key algorithm"
	}
}

// GetPublicKeyAlgorithm returns the PublicKeyAlgorithm constant for a given public key.
//
// This is a helper function for code that needs to determine the algorithm type
// from a crypto.PublicKey. In Agiligo, you should prefer type switches or using
// the crypto.PublicKeyAlgorithm interface methods.
func GetPublicKeyAlgorithm(pub crypto.PublicKey) PublicKeyAlgorithm {
	switch pub.(type) {
	case *rsa.PublicKey:
		return RSA
	case *ecdsa.PublicKey:
		return ECDSA
	case ed25519.PublicKey:
		return Ed25519
	default:
		return UnknownPublicKeyAlgorithm
	}
}

// SignatureAlgorithm represents a signature algorithm.
//
// In Agiligo, these are replaced by the crypto.SignatureAlgorithm interface
// and dynamic registration. This type exists for backward compatibility.
type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	MD2WithRSA                                    // Deprecated: MD2 is not secure
	MD5WithRSA                                    // Deprecated: MD5 is not secure
	SHA1WithRSA                                   // Deprecated: SHA-1 is not secure
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	DSAWithSHA1   // Deprecated: DSA is not secure, SHA-1 is not secure
	DSAWithSHA256 // Deprecated: DSA is not secure
	ECDSAWithSHA1 // Deprecated: SHA-1 is not secure
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
	PureEd25519
)

// String returns the name of the signature algorithm.
func (algo SignatureAlgorithm) String() string {
	switch algo {
	case MD2WithRSA:
		return "MD2-RSA"
	case MD5WithRSA:
		return "MD5-RSA"
	case SHA1WithRSA:
		return "SHA1-RSA"
	case SHA256WithRSA:
		return "SHA256-RSA"
	case SHA384WithRSA:
		return "SHA384-RSA"
	case SHA512WithRSA:
		return "SHA512-RSA"
	case DSAWithSHA1:
		return "DSA-SHA1"
	case DSAWithSHA256:
		return "DSA-SHA256"
	case ECDSAWithSHA1:
		return "ECDSA-SHA1"
	case ECDSAWithSHA256:
		return "ECDSA-SHA256"
	case ECDSAWithSHA384:
		return "ECDSA-SHA384"
	case ECDSAWithSHA512:
		return "ECDSA-SHA512"
	case SHA256WithRSAPSS:
		return "SHA256-RSAPSS"
	case SHA384WithRSAPSS:
		return "SHA384-RSAPSS"
	case SHA512WithRSAPSS:
		return "SHA512-RSAPSS"
	case PureEd25519:
		return "Ed25519"
	default:
		return "unknown signature algorithm"
	}
}

// IsRSA returns true if the public key is an RSA key.
func IsRSA(pub crypto.PublicKey) bool {
	_, ok := pub.(*rsa.PublicKey)
	return ok
}

// IsECDSA returns true if the public key is an ECDSA key.
func IsECDSA(pub crypto.PublicKey) bool {
	_, ok := pub.(*ecdsa.PublicKey)
	return ok
}

// IsEd25519 returns true if the public key is an Ed25519 key.
func IsEd25519(pub crypto.PublicKey) bool {
	_, ok := pub.(ed25519.PublicKey)
	return ok
}
