// Package x509compat provides compatibility shims for code written against
// standard Go's crypto/x509 package to work with Agiligo's reorganized crypto APIs.
//
// Agiligo moved many x509 functions to algorithm-specific packages:
//   - PKCS1 functions moved to crypto/rsa
//   - EC private key functions moved to crypto/ecdsa
//   - PKCS8 functions moved to crypto/pkcs8
//   - PKIX public key functions moved to crypto/x509/pkix and crypto/x509/pkix/pkixparser
//
// This package wraps the new locations with the old function names for backward compatibility.
package x509compat

import (
	"crypto"
	_ "crypto/init" // Register all algorithms
	"crypto/ecdsa"
	"crypto/pkcs8"
	"crypto/rsa"
	"crypto/x509/pkix"
	"crypto/x509/pkix/pkixparser"
)

// ParsePKCS1PrivateKey parses an RSA private key in PKCS #1, ASN.1 DER form.
//
// This function wraps crypto/rsa.ParsePKCS1PrivateKey for compatibility with
// code expecting crypto/x509.ParsePKCS1PrivateKey.
func ParsePKCS1PrivateKey(der []byte) (*rsa.PrivateKey, error) {
	return rsa.ParsePKCS1PrivateKey(der)
}

// MarshalPKCS1PrivateKey converts an RSA private key to PKCS #1, ASN.1 DER form.
//
// This function wraps crypto/rsa.MarshalPKCS1PrivateKey for compatibility with
// code expecting crypto/x509.MarshalPKCS1PrivateKey.
func MarshalPKCS1PrivateKey(key *rsa.PrivateKey) []byte {
	return rsa.MarshalPKCS1PrivateKey(key)
}

// ParsePKCS1PublicKey parses an RSA public key in PKCS #1, ASN.1 DER form.
//
// This function wraps crypto/rsa.ParsePKCS1PublicKey for compatibility with
// code expecting crypto/x509.ParsePKCS1PublicKey.
func ParsePKCS1PublicKey(der []byte) (*rsa.PublicKey, error) {
	return rsa.ParsePKCS1PublicKey(der)
}

// MarshalPKCS1PublicKey converts an RSA public key to PKCS #1, ASN.1 DER form.
//
// This function wraps crypto/rsa.MarshalPKCS1PublicKey for compatibility with
// code expecting crypto/x509.MarshalPKCS1PublicKey.
func MarshalPKCS1PublicKey(key *rsa.PublicKey) []byte {
	return rsa.MarshalPKCS1PublicKey(key)
}

// ParseECPrivateKey parses an EC private key in SEC 1, ASN.1 DER form.
//
// This function wraps crypto/ecdsa.ParseECPrivateKey for compatibility with
// code expecting crypto/x509.ParseECPrivateKey.
func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	return ecdsa.ParseECPrivateKey(der)
}

// MarshalECPrivateKey converts an EC private key to SEC 1, ASN.1 DER form.
//
// This function wraps crypto/ecdsa.MarshalECPrivateKey for compatibility with
// code expecting crypto/x509.MarshalECPrivateKey.
func MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	return ecdsa.MarshalECPrivateKey(key)
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey (not a pointer),
// or *ecdh.PrivateKey (for X25519). More types might be supported in the future.
//
// This function wraps crypto/pkcs8.UnmarshalPKCS8PrivateKey for compatibility with
// code expecting crypto/x509.ParsePKCS8PrivateKey.
func ParsePKCS8PrivateKey(der []byte) (crypto.PrivateKey, error) {
	return pkcs8.UnmarshalPKCS8PrivateKey(der)
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PrivateKey,
// *ecdsa.PrivateKey, ed25519.PrivateKey (not a pointer), and *ecdh.PrivateKey.
// Unsupported key types result in an error.
//
// This function wraps crypto/pkcs8.MarshalPKCS8PrivateKey for compatibility with
// code expecting crypto/x509.MarshalPKCS8PrivateKey.
func MarshalPKCS8PrivateKey(key crypto.PrivateKey) ([]byte, error) {
	return pkcs8.MarshalPKCS8PrivateKey(key)
}

// ParsePKIXPublicKey parses a public key in PKIX, ASN.1 DER form.
// The encoded public key is a SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
//
// It returns a *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey (not a pointer),
// or *ecdh.PublicKey (for X25519). More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
//
// This function wraps the two-step process in Agiligo:
//   1. pkix.UnmarshalPKIXPublicKeyInfo (parses DER to struct)
//   2. pkixparser.GetPublicKeyFromPKIXPublicKeyInfo (extracts public key)
func ParsePKIXPublicKey(derBytes []byte) (crypto.PublicKey, error) {
	pki, err := pkix.UnmarshalPKIXPublicKeyInfo(derBytes)
	if err != nil {
		return nil, err
	}
	return pkixparser.GetPublicKeyFromPKIXPublicKeyInfo(pki)
}

// MarshalPKIXPublicKey converts a public key to PKIX, ASN.1 DER form.
// The encoded public key is a SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
//
// The following key types are currently supported: *rsa.PublicKey,
// *ecdsa.PublicKey, ed25519.PublicKey (not a pointer), and *ecdh.PublicKey.
// Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PUBLIC KEY".
//
// This function wraps the two-step process in Agiligo:
//   1. pkixparser.GetPKIXPublicKeyInfoFromPublicKey (creates struct with key bytes)
//   2. pkix.MarshalPKIXPublicKeyInfo (marshals to DER)
func MarshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error) {
	pki, err := pkixparser.GetPKIXPublicKeyInfoFromPublicKey(pub)
	if err != nil {
		return nil, err
	}

	return pkix.MarshalPKIXPublicKeyInfo(
		pki.PublicKey.Bytes,
		&pki.AlgorithmIdentifier,
	)
}
