package sshutil

import (
	"crypto/dsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"go.step.sm/crypto/internal/emoji"
	"golang.org/x/crypto/ssh"
)

// FingerprintEncoding defines the supported encodings in SSH key and
// certificate fingerprints.
type FingerprintEncoding int

// Supported fingerprint encodings.
const (
	// Base64RawFingerprint represents the base64RawStd encoding of the
	// fingerprint. This is the default encoding for an SSH key.
	Base64RawFingerprint FingerprintEncoding = iota
	// Base64RawURLFingerprint represents the base64RawURL encoding of the
	// fingerprint.
	Base64RawURLFingerprint
	// Base64Fingerprint represents the base64 encoding of the fingerprint.
	Base64Fingerprint
	// Base64UrlFingerprint represents the base64URL encoding of the
	// fingerprint.
	Base64UrlFingerprint FingerprintEncoding = iota
	// HexFingerprint represents the hex encoding of the fingerprint.
	HexFingerprint
	// EmojiFingerprint represents the emoji encoding of the fingerprint.
	EmojiFingerprint
)

// Fingerprint returns the SHA-256 fingerprint of an ssh public key or
// certificate.
func Fingerprint(pub ssh.PublicKey) string {
	return EncodedFingerprint(pub, Base64RawFingerprint)
}

// EncodedFingerprint returns an encoded the SHA-256 fingerprint of an ssh
// public key or certificate using the specified encoding. In an invalid
// encoding is passed, the return value will be an empty string.
func EncodedFingerprint(pub ssh.PublicKey, encoding FingerprintEncoding) string {
	const prefix = "SHA256:"

	sum := sha256.Sum256(pub.Marshal())
	switch encoding {
	case Base64RawFingerprint:
		return prefix + base64.RawStdEncoding.EncodeToString(sum[:])
	case Base64RawURLFingerprint:
		return prefix + base64.RawURLEncoding.EncodeToString(sum[:])
	case Base64Fingerprint:
		return prefix + base64.StdEncoding.EncodeToString(sum[:])
	case Base64UrlFingerprint:
		return prefix + base64.URLEncoding.EncodeToString(sum[:])
	case HexFingerprint:
		return prefix + strings.ToLower(hex.EncodeToString(sum[:]))
	case EmojiFingerprint:
		return prefix + emoji.Emoji(sum[:])
	default:
		return ""
	}
}

// FormatFingerprint gets a public key from an authorized_keys file used in
// OpenSSH and returns the fingerprint in the following format:
//
//	<size> SHA256:<base64-raw-fingerprint> <comment> (<type)
func FormatFingerprint(in []byte, encoding FingerprintEncoding) (string, error) {
	key, comment, _, _, err := ssh.ParseAuthorizedKey(in)
	if err != nil {
		return "", fmt.Errorf("error parsing public key: %w", err)
	}
	if comment == "" {
		comment = "no comment"
	}

	typ, size, err := publicKeyTypeAndSize(key)
	if err != nil {
		return "", fmt.Errorf("error determining key type and size: %w", err)
	}

	fp := EncodedFingerprint(key, encoding)
	if fp == "" {
		return "", fmt.Errorf("unsupported encoding format %v", encoding)
	}

	return fmt.Sprintf("%d %s %s (%s)", size, fp, comment, typ), nil
}

func publicKeyTypeAndSize(key ssh.PublicKey) (string, int, error) {
	var isCert bool
	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
		isCert = true
	}

	var typ string
	var size int
	switch key.Type() {
	case ssh.KeyAlgoECDSA256:
		typ, size = "ECDSA", 256
	case ssh.KeyAlgoECDSA384:
		typ, size = "ECDSA", 384
	case ssh.KeyAlgoECDSA521:
		typ, size = "ECDSA", 521
	case ssh.KeyAlgoSKECDSA256:
		typ, size = "SK-ECDSA", 256
	case ssh.KeyAlgoED25519:
		typ, size = "ED25519", 256
	case ssh.KeyAlgoSKED25519:
		typ, size = "SK-ED25519", 256
	case ssh.KeyAlgoRSA:
		typ = "RSA"
		cpk, err := CryptoPublicKey(key)
		if err != nil {
			return "", 0, err
		}
		k, ok := cpk.(*rsa.PublicKey)
		if !ok {
			return "", 0, errors.New("unsupported key: not an RSA public key")
		}
		size = 8 * k.Size()
	case ssh.KeyAlgoDSA:
		typ = "DSA"
		cpk, err := CryptoPublicKey(key)
		if err != nil {
			return "", 0, err
		}
		k, ok := cpk.(*dsa.PublicKey)
		if !ok {
			return "", 0, errors.New("unsupported key: not an DSA public key")
		}
		size = k.Parameters.P.BitLen()
	default:
		return "", 0, errors.Errorf("public key %s is not supported", key.Type())
	}

	if isCert {
		typ += "-CERT"
	}

	return typ, size, nil
}
