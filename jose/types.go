// Package jose is a wrapper for github.com/go-jose/go-jose/v4 and implements
// utilities to parse and generate JWT, JWK and JWKSets.
package jose

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"

	"go.step.sm/crypto/x25519"
)

// SupportsPBKDF2 constant to know if the underlaying library supports
// password based cryptography algorithms.
const SupportsPBKDF2 = true

// PBKDF2SaltSize is the default size of the salt for PBKDF2, 128-bit salt.
const PBKDF2SaltSize = 16

// PBKDF2Iterations is the default number of iterations for PBKDF2.
//
// 600k is the current OWASP recommendation (Dec 2022)
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
//
// Nist recommends at least 10k (800-63B), 1Password increased in 2023 the
// number of iterations from 100k to 650k.
const PBKDF2Iterations = 600000

// JSONWebSignature represents a signed JWS object after parsing.
type JSONWebSignature = jose.JSONWebSignature

// JSONWebToken represents a JSON Web Token (as specified in RFC7519).
type JSONWebToken = jwt.JSONWebToken

// JSONWebKey represents a public or private key in JWK format.
type JSONWebKey = jose.JSONWebKey

// JSONWebKeySet represents a JWK Set object.
type JSONWebKeySet = jose.JSONWebKeySet

// JSONWebEncryption represents an encrypted JWE object after parsing.
type JSONWebEncryption = jose.JSONWebEncryption

// Recipient represents an algorithm/key to encrypt messages to.
type Recipient = jose.Recipient

// EncrypterOptions represents options that can be set on new encrypters.
type EncrypterOptions = jose.EncrypterOptions

// Encrypter represents an encrypter which produces an encrypted JWE object.
type Encrypter = jose.Encrypter

// ContentType represents type of the contained data.
type ContentType = jose.ContentType

// KeyAlgorithm represents a key management algorithm.
type KeyAlgorithm = jose.KeyAlgorithm

// ContentEncryption represents a content encryption algorithm.
type ContentEncryption = jose.ContentEncryption

// SignatureAlgorithm represents a signature (or MAC) algorithm.
type SignatureAlgorithm = jose.SignatureAlgorithm

// Signature represents a signature.
type Signature = jose.Signature

// ErrCryptoFailure indicates an error in a cryptographic primitive.
var ErrCryptoFailure = jose.ErrCryptoFailure

// ErrInvalidKeySize indicates that the given key is not the correct size for
// the selected algorithm, e.g. an HMAC key shorter than the hash output. It is
// only returned when signing, go-jose wraps it in a generic error when
// verifying an HMAC signature. Use ValidateJWK to detect short HMAC keys
// before verifying.
var ErrInvalidKeySize = jose.ErrInvalidKeySize

// Claims represents public claim values (as specified in RFC 7519).
type Claims = jwt.Claims

// Builder is a utility for making JSON Web Tokens. Calls can be chained, and
// errors are accumulated until the final call to Serialize.
type Builder = jwt.Builder

// NumericDate represents date and time as the number of seconds since the
// epoch, including leap seconds. Non-integer values can be represented
// in the serialized format, but we round to the nearest second.
type NumericDate = jwt.NumericDate

// Audience represents the recipients that the token is intended for.
type Audience = jwt.Audience

// Expected defines values used for protected claims validation.
// If field has zero value then validation is skipped.
type Expected = jwt.Expected

// Signer represents a signer which takes a payload and produces a signed JWS object.
type Signer = jose.Signer

// OpaqueSigner represents a jose.Signer that wraps a crypto.Signer
type OpaqueSigner = jose.OpaqueSigner

// SigningKey represents an algorithm/key used to sign a message.
type SigningKey = jose.SigningKey

// SignerOptions represents options that can be set when creating signers.
type SignerOptions = jose.SignerOptions

// Header represents the read-only JOSE header for JWE/JWS objects.
type Header = jose.Header

// HeaderKey represents the type used as a key in the protected header of a JWS
// object.
type HeaderKey = jose.HeaderKey

// ErrInvalidIssuer indicates invalid iss claim.
var ErrInvalidIssuer = jwt.ErrInvalidIssuer

// ErrInvalidAudience indicated invalid aud claim.
var ErrInvalidAudience = jwt.ErrInvalidAudience

// ErrNotValidYet indicates that token is used before time indicated in nbf claim.
var ErrNotValidYet = jwt.ErrNotValidYet

// ErrExpired indicates that token is used after expiry time indicated in exp claim.
var ErrExpired = jwt.ErrExpired

// ErrInvalidSubject indicates invalid sub claim.
var ErrInvalidSubject = jwt.ErrInvalidSubject

// ErrInvalidID indicates invalid jti claim.
var ErrInvalidID = jwt.ErrInvalidID

// ErrIssuedInTheFuture indicates that the iat field is in the future.
var ErrIssuedInTheFuture = jwt.ErrIssuedInTheFuture

// Key management algorithms
//
//nolint:staticcheck,revive // use standard names in upper-case
const (
	RSA1_5             = KeyAlgorithm("RSA1_5")             // RSA-PKCS1v1.5
	RSA_OAEP           = KeyAlgorithm("RSA-OAEP")           // RSA-OAEP-SHA1
	RSA_OAEP_256       = KeyAlgorithm("RSA-OAEP-256")       // RSA-OAEP-SHA256
	A128KW             = KeyAlgorithm("A128KW")             // AES key wrap (128)
	A192KW             = KeyAlgorithm("A192KW")             // AES key wrap (192)
	A256KW             = KeyAlgorithm("A256KW")             // AES key wrap (256)
	DIRECT             = KeyAlgorithm("dir")                // Direct encryption
	ECDH_ES            = KeyAlgorithm("ECDH-ES")            // ECDH-ES
	ECDH_ES_A128KW     = KeyAlgorithm("ECDH-ES+A128KW")     // ECDH-ES + AES key wrap (128)
	ECDH_ES_A192KW     = KeyAlgorithm("ECDH-ES+A192KW")     // ECDH-ES + AES key wrap (192)
	ECDH_ES_A256KW     = KeyAlgorithm("ECDH-ES+A256KW")     // ECDH-ES + AES key wrap (256)
	A128GCMKW          = KeyAlgorithm("A128GCMKW")          // AES-GCM key wrap (128)
	A192GCMKW          = KeyAlgorithm("A192GCMKW")          // AES-GCM key wrap (192)
	A256GCMKW          = KeyAlgorithm("A256GCMKW")          // AES-GCM key wrap (256)
	PBES2_HS256_A128KW = KeyAlgorithm("PBES2-HS256+A128KW") // PBES2 + HMAC-SHA256 + AES key wrap (128)
	PBES2_HS384_A192KW = KeyAlgorithm("PBES2-HS384+A192KW") // PBES2 + HMAC-SHA384 + AES key wrap (192)
	PBES2_HS512_A256KW = KeyAlgorithm("PBES2-HS512+A256KW") // PBES2 + HMAC-SHA512 + AES key wrap (256)
)

// Signature algorithms
const (
	HS256  = "HS256"  // HMAC using SHA-256
	HS384  = "HS384"  // HMAC using SHA-384
	HS512  = "HS512"  // HMAC using SHA-512
	RS256  = "RS256"  // RSASSA-PKCS-v1.5 using SHA-256
	RS384  = "RS384"  // RSASSA-PKCS-v1.5 using SHA-384
	RS512  = "RS512"  // RSASSA-PKCS-v1.5 using SHA-512
	ES256  = "ES256"  // ECDSA using P-256 and SHA-256
	ES384  = "ES384"  // ECDSA using P-384 and SHA-384
	ES512  = "ES512"  // ECDSA using P-521 and SHA-512
	PS256  = "PS256"  // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384  = "PS384"  // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512  = "PS512"  // RSASSA-PSS using SHA512 and MGF1-SHA512
	EdDSA  = "EdDSA"  // Ed25519 with EdDSA signature schema
	XEdDSA = "XEdDSA" // X25519 with XEdDSA signature schema
)

// Content encryption algorithms
//
//nolint:revive,staticcheck // use standard names in upper-case
const (
	A128CBC_HS256 = ContentEncryption("A128CBC-HS256") // AES-CBC + HMAC-SHA256 (128)
	A192CBC_HS384 = ContentEncryption("A192CBC-HS384") // AES-CBC + HMAC-SHA384 (192)
	A256CBC_HS512 = ContentEncryption("A256CBC-HS512") // AES-CBC + HMAC-SHA512 (256)
	A128GCM       = ContentEncryption("A128GCM")       // AES-GCM (128)
	A192GCM       = ContentEncryption("A192GCM")       // AES-GCM (192)
	A256GCM       = ContentEncryption("A256GCM")       // AES-GCM (256)
)

// Elliptic curves
const (
	P256 = "P-256" // P-256 curve (FIPS 186-3)
	P384 = "P-384" // P-384 curve (FIPS 186-3)
	P521 = "P-521" // P-521 curve (FIPS 186-3)
)

// Key types
const (
	EC  = "EC"  // Elliptic curves
	RSA = "RSA" // RSA
	OKP = "OKP" // Ed25519
	OCT = "oct" // Octet sequence
)

// Ed25519 is the EdDSA signature scheme using SHA-512/256 and Curve25519
const Ed25519 = "Ed25519"

// Default key management, signature, and content encryption algorithms to use if none is specified.
const (
	// Key management algorithms
	DefaultECKeyAlgorithm  = ECDH_ES
	DefaultRSAKeyAlgorithm = RSA_OAEP_256
	DefaultOctKeyAlgorithm = A256GCMKW
	// Signature algorithms
	DefaultRSASigAlgorithm = RS256
	DefaultOctSigAlgorithm = HS256
	// Content encryption algorithm
	DefaultEncAlgorithm = A256GCM
)

// Default sizes
const (
	DefaultRSASize = 2048
	DefaultOctSize = 32
)

// supportedKeyAlgorithms is the list of key management algorithms accepted
// when parsing a JWE.
var supportedKeyAlgorithms = []KeyAlgorithm{
	RSA1_5, RSA_OAEP, RSA_OAEP_256,
	A128KW, A192KW, A256KW,
	DIRECT,
	ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW,
	A128GCMKW, A192GCMKW, A256GCMKW,
	PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW,
}

// supportedContentEncryption is the list of content encryption algorithms
// accepted when parsing a JWE.
var supportedContentEncryption = []ContentEncryption{
	A128CBC_HS256, A192CBC_HS384, A256CBC_HS512,
	A128GCM, A192GCM, A256GCM,
}

// supportedSignatureAlgorithms is the list of signature algorithms accepted
// when parsing a JWS or a JWT.
var supportedSignatureAlgorithms = []SignatureAlgorithm{
	HS256, HS384, HS512,
	RS256, RS384, RS512,
	ES256, ES384, ES512,
	PS256, PS384, PS512,
	EdDSA, XEdDSA,
}

// ParseEncrypted parses an encrypted message in compact or full serialization format.
func ParseEncrypted(input string) (*JSONWebEncryption, error) {
	return jose.ParseEncrypted(input, supportedKeyAlgorithms, supportedContentEncryption)
}

// NewEncrypter creates an appropriate encrypter based on the key type.
func NewEncrypter(enc ContentEncryption, rcpt Recipient, opts *EncrypterOptions) (Encrypter, error) {
	return jose.NewEncrypter(enc, rcpt, opts)
}

// NewNumericDate constructs NumericDate from time.Time value.
func NewNumericDate(t time.Time) *NumericDate {
	return jwt.NewNumericDate(t)
}

// UnixNumericDate returns a NumericDate from the given seconds since the UNIX
// Epoch time. For backward compatibility is s is 0, a nil value will be returned.
func UnixNumericDate(s int64) *NumericDate {
	if s == 0 {
		return nil
	}
	out := NumericDate(s)
	return &out
}

// NewSigner creates an appropriate signer based on the key type
func NewSigner(sig SigningKey, opts *SignerOptions) (Signer, error) {
	sig.Key = guessOpaqueSigner(sig.Key)
	if sig.Algorithm == "" {
		sig.Algorithm = guessSignatureAlgorithm(sig.Key)
	}
	return jose.NewSigner(sig, opts)
}

// NewOpaqueSigner creates a new OpaqueSigner for JWT signing from a crypto.Signer
func NewOpaqueSigner(signer crypto.Signer) OpaqueSigner {
	return cryptosigner.Opaque(signer)
}

// Verify validates the token payload with the given public key and deserializes
// the token into the destination.
func Verify(token *JSONWebToken, publicKey any, dest ...any) error {
	if k, ok := publicKey.(x25519.PublicKey); ok {
		publicKey = X25519Verifier(k)
	}
	return token.Claims(publicKey, dest...)
}

// ParseSigned parses token from JWS form. It supports the compact
// serialization format, and the JSON serialization format with a single
// signature and without unprotected headers.
func ParseSigned(s string) (*JSONWebToken, error) {
	// go-jose v4 jwt.ParseSigned no longer strips whitespace, keep the v3
	// behavior so tokens with surrounding spaces or tabs are still accepted.
	s = stripWhitespace(s)

	// go-jose v4 jwt.ParseSigned only supports the compact serialization
	// format, keep the v3 behavior and convert JSON tokens to compact.
	if strings.HasPrefix(s, "{") {
		var err error
		if s, err = jsonToCompact(s); err != nil {
			return nil, err
		}
	}

	return jwt.ParseSigned(s, supportedSignatureAlgorithms)
}

// jsonToCompact converts a JWS in the flattened or general JSON serialization
// format to the compact serialization format. It reuses the original base64url
// segments, re-encoding the protected header might change the signed bytes.
func jsonToCompact(s string) (string, error) {
	type rawSignature struct {
		Protected string          `json:"protected"`
		Header    json.RawMessage `json:"header"`
		Signature string          `json:"signature"`
	}
	var v struct {
		Payload    *string        `json:"payload"`
		Signatures []rawSignature `json:"signatures"`
		rawSignature
	}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", fmt.Errorf("error parsing JWS: %w", err)
	}

	sig := v.rawSignature
	switch {
	case len(v.Signatures) == 1:
		sig = v.Signatures[0]
	case len(v.Signatures) > 1:
		return "", errors.New("too many signatures in payload; expecting only one")
	}
	if v.Payload == nil {
		return "", errors.New("missing payload in JWS message")
	}
	if sig.Protected == "" || (len(sig.Header) > 0 && string(sig.Header) != "null") {
		return "", errors.New("JWT requires a protected header and no unprotected header")
	}

	return sig.Protected + "." + *v.Payload + "." + sig.Signature, nil
}

// stripWhitespace removes all the whitespace characters from the given
// string.
func stripWhitespace(s string) string {
	if strings.IndexFunc(s, unicode.IsSpace) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

// Signed creates builder for signed tokens.
func Signed(sig Signer) Builder {
	return jwt.Signed(sig)
}

// ParseJWS parses a signed message in compact or full serialization format.
func ParseJWS(s string) (*JSONWebSignature, error) {
	return jose.ParseSigned(s, supportedSignatureAlgorithms)
}

// Determine whether a JSONWebKey is symmetric
func IsSymmetric(k *JSONWebKey) bool {
	switch k.Key.(type) {
	case []byte:
		return true
	default:
		return false
	}
}

// Determine whether a JSONWebKey is asymmetric
func IsAsymmetric(k *JSONWebKey) bool {
	return !IsSymmetric(k)
}

// TrimPrefix removes the string "go-jose/go-jose" from all errors.
func TrimPrefix(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(strings.TrimPrefix(err.Error(), "go-jose/go-jose: "))
}
