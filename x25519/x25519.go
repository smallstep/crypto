package x25519

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"io"
	"strconv"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
	"golang.org/x/crypto/curve25519"
)

const (
	// PrivateKeySize is the size in bytes of a X25519 private key.
	PrivateKeySize = 32

	// PublicKeySize is the size in bytes of a X25519 public key.
	PublicKeySize = 32

	// SignatureSize is the size in bytes of a XEdDSA signature.
	SignatureSize = 64
)

var one = (&field.Element{}).One()

// PrivateKey is the type used to represent a X25519 private key.
type PrivateKey []byte

// PublicKey is the type used to represent a X25519 public key.
type PublicKey []byte

// GenerateKey generates a public/private key pair using entropy from random. If
// random is nil, crypto/rand.Reader will be used.
func GenerateKey(random io.Reader) (PublicKey, PrivateKey, error) {
	if random == nil {
		random = rand.Reader
	}

	priv := make([]byte, PrivateKeySize)
	if _, err := io.ReadFull(random, priv); err != nil {
		return nil, nil, err
	}

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}

	return pub, priv, err
}

// ToEd25519 converts the public key p into a ed25519 key.
//
// (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
func (p PublicKey) ToEd25519() (ed25519.PublicKey, error) {
	a, err := convertMont(p)
	if err != nil {
		return nil, err
	}
	return a.Bytes(), nil
}

// Equal reports whether p and x have the same value.
func (p PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(p, xx)
}

// Public returns the public key using scalar multiplication (scalar * point)
// using the Curve25519 basepoint. It will return nil if the private key is not
// a valid one.
func (p PrivateKey) Public() crypto.PublicKey {
	pub, err := p.PublicKey()
	if err != nil {
		return nil
	}
	return pub
}

// Equal reports whether p and x have the same value. The comparison is done
// in constant time.
func (p PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(p, xx) == 1
}

// PublicKey returns the public key using scalar multiplication (scalar * point)
// using the Curve25519 basepoint.
func (p PrivateKey) PublicKey() (PublicKey, error) {
	pub, err := curve25519.X25519(p, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// SharedKey returns the result of the scalar multiplication (scalar * point),
// using the PrivateKey as the scalar value and the given key as the point. Both
// scalar and point must be slices of 32 bytes.
func (p PrivateKey) SharedKey(peerPublicKey []byte) ([]byte, error) {
	sharedKey, err := curve25519.X25519(p, peerPublicKey)
	if err != nil {
		return nil, err
	}
	return sharedKey, nil
}

// Sign signs the given message with the private key p and returns a signature.
// If random is nil, crypto/rand.Reader will be used.
//
// It implements the XEdDSA sign method defined in
// https://signal.org/docs/specifications/xeddsa/#xeddsa
//
// XEdDSA performs two passes over messages to be signed and therefore cannot
// handle pre-hashed messages. Thus opts.HashFunc() must return zero to indicate
// the message hasn't been hashed. This can be achieved by passing
// crypto.Hash(0) or nil as the value for opts.
func (p PrivateKey) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("x25519: cannot sign hashed message")
	}

	return Sign(random, p, message)
}

// Sign signs the message with the private key p and returns a signature. It
// will panic if len(p) is not PrivateKeySize. If random is nil,
// crypto/rand.Reader will be used.
//
// It implements the XEdDSA sign method defined in
// https://signal.org/docs/specifications/xeddsa/#xeddsa
//
//	xeddsa_sign(k, M, Z):
//	    A, a = calculate_key_pair(k)
//	    r = hash1(a || M || Z) (mod q)
//	    R = rB
//	    h = hash(R || A || M) (mod q)
//	    s = r + ha (mod q)
//	    return R || s
//
// The signatures always use the format of the specification, with the most
// significant bit of s set to 0, which is accepted by verifiers of the
// specification and by libsignal and libsignal-protocol-c.
//
// The nonce r is derived like the xed25519_sign function of
// libsignal-protocol-c, which differs from the specification when the private
// key is not negated: the clamped bytes of k are hashed instead of the encoding
// of a = k (mod q). The nonce is not visible to verifiers, and both choices are
// equally secure, but this one generates the same signatures as xed25519_sign
// for the same clamped private key and random bytes, so its test vectors can be
// used.
func Sign(random io.Reader, p PrivateKey, message []byte) (signature []byte, err error) {
	if l := len(p); l != PrivateKeySize {
		panic("x25519: bad private key length: " + strconv.Itoa(l))
	}
	if random == nil {
		random = rand.Reader
	}

	pub, priv, negated, err := p.calculateKeyPair()
	if err != nil {
		return nil, err
	}

	// Select the encoding of a if k was negated, and the clamped bytes of k
	// otherwise, in constant time.
	nonceKey := clamp(p)
	subtle.ConstantTimeCopy(negated, nonceKey, priv.Bytes())

	randomZ := make([]byte, 64)
	if _, err := io.ReadFull(random, randomZ); err != nil {
		return nil, err
	}

	// hash1(X) is defined as hash(2^b - 1 - 1 || X), with b = 256, the prefix
	// is the 32 bytes little-endian encoding of 2^256 - 2. It separates the
	// nonce hash from the hash used for h.
	prefix := [32]byte{
		0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}

	rh := sha512.New()
	rh.Write(prefix[:])
	rh.Write(nonceKey)
	rh.Write(message)
	rh.Write(randomZ)
	rDigest := make([]byte, 0, sha512.Size)
	rDigest = rh.Sum(rDigest)

	r, err := edwards25519.NewScalar().SetUniformBytes(rDigest)
	if err != nil {
		return nil, err
	}

	rB := (&edwards25519.Point{}).ScalarBaseMult(r).Bytes()

	hh := sha512.New()
	hh.Write(rB)
	hh.Write(pub)
	hh.Write(message)
	hDigest := make([]byte, 0, sha512.Size)
	hDigest = hh.Sum(hDigest)
	h, err := edwards25519.NewScalar().SetUniformBytes(hDigest)
	if err != nil {
		return nil, err
	}

	s := (&edwards25519.Scalar{}).Add(r, h.Multiply(h, priv))

	sig := make([]byte, 64)
	copy(sig[:32], rB)
	copy(sig[32:], s.Bytes())
	return sig, nil
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not PublicKeySize.
//
// It implements the XEdDSA verify method defined in
// https://signal.org/docs/specifications/xeddsa/#xeddsa
//
//	xeddsa_verify(u, M, (R || s)):
//	    if u >= p or R.y >= 2^|p| or s >= 2^|q|:
//	        return false
//	    A = convert_mont(u)
//	    if not on_curve(A):
//	        return false
//	    h = hash(R || A || M) (mod q)
//	    Rcheck = sB - hA
//	    if bytes_equal(R, Rcheck):
//	        return true
//	    return false
//
// Verify is stricter than the specification in two cases:
//
//   - It rejects signatures with s >= q. The specification only rejects
//     s >= 2^253, and if s + q < 2^253, s and s + q are both valid, so anyone
//     could create a second valid signature for the same message without the
//     private key.
//   - It rejects public keys of small order. The specification accepts them,
//     but signatures for them can be forged without the private key.
//
// Honest signers never generate any of these, so they are not relaxed for
// compatibility.
//
// Verify does not accept the signature format used by libsignal and by the
// curve25519_sign function of libsignal-protocol-c, which is not part of the
// specification. Instead of negating the private key, that format keeps the
// sign bit of the twisted Edwards public key in the most significant bit of s,
// so those signatures are rejected when that bit is set, as s >= 2^253.
//
// For public keys that are canonical and not of small order, the following
// code should be equivalent:
//
//	pub, err := publicKey.ToEd25519()
//	if err != nil {
//	    return false
//	}
//	return ed25519.Verify(pub, message, sig)
func Verify(publicKey PublicKey, message, sig []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("x25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize || sig[63]&0xE0 != 0 {
		return false
	}

	// Reject u >= p, field.Element.SetBytes ignores the most significant bit
	// and accepts non-canonical values.
	if !isReduced(publicKey) {
		return false
	}

	a, err := convertMont(publicKey)
	if err != nil {
		return false
	}

	// Reject public keys of small order, signatures for them can be forged
	// without the private key.
	if (&edwards25519.Point{}).MultByCofactor(a).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}

	hh := sha512.New()
	hh.Write(sig[:32])
	hh.Write(a.Bytes())
	hh.Write(message)
	hDigest := make([]byte, 0, sha512.Size)
	hDigest = hh.Sum(hDigest)
	h, err := edwards25519.NewScalar().SetUniformBytes(hDigest)
	if err != nil {
		return false
	}

	s, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}

	minusA := (&edwards25519.Point{}).Negate(a)
	r := (&edwards25519.Point{}).VarTimeDoubleScalarBaseMult(h, minusA, s)
	return subtle.ConstantTimeCompare(sig[:32], r.Bytes()) == 1
}

// calculateKeyPair converts a Montgomery private key k to a twisted Edwards
// public key and private key (A, a) as defined in
// https://signal.org/docs/specifications/xeddsa/#elliptic-curve-conversions
//
//	calculate_key_pair(k):
//	    E = kB
//	    A.y = E.y
//	    A.s = 0
//	    if E.s == 1:
//	        a = -k (mod q)
//	    else:
//	        a = k (mod q)
//	    return A, a
//
// It also returns E.s, 1 if k was negated and 0 otherwise, which Sign uses to
// derive the nonce. E.s is not part of the public key, so a is selected in
// constant time.
func (p PrivateKey) calculateKeyPair() ([]byte, *edwards25519.Scalar, int, error) {
	k, err := edwards25519.NewScalar().SetBytesWithClamping(p)
	if err != nil {
		return nil, nil, 0, err
	}

	pub := (&edwards25519.Point{}).ScalarBaseMult(k).Bytes()
	signBit := int(pub[31] >> 7)
	// Set sign bit to 0
	pub[31] &= 0x7F

	// Both k and -k are reduced, SetUniformBytes is used instead of
	// SetCanonicalBytes because the latter is not constant time.
	wide := make([]byte, 64)
	copy(wide, k.Bytes())
	subtle.ConstantTimeCopy(signBit, wide[:32], edwards25519.NewScalar().Negate(k).Bytes())
	a, err := edwards25519.NewScalar().SetUniformBytes(wide)
	if err != nil {
		return nil, nil, 0, err
	}

	return pub, a, signBit, nil
}

// clamp returns a copy of k clamped as defined in RFC 7748.
func clamp(k []byte) []byte {
	c := bytes.Clone(k)
	c[0] &= 248
	c[31] &= 127
	c[31] |= 64
	return c
}

// convertMont converts from a Montgomery u-coordinate to a twisted Edwards
// point P, according to
// https://signal.org/docs/specifications/xeddsa/#elliptic-curve-conversions
//
//	convert_mont(u):
//	  umasked = u (mod 2^|p|)
//	  P.y = u_to_y(umasked)
//	  P.s = 0
//	  return P
func convertMont(u PublicKey) (*edwards25519.Point, error) {
	um, err := (&field.Element{}).SetBytes(u)
	if err != nil {
		return nil, err
	}

	// y = (u - 1)/(u + 1)
	a := new(field.Element).Subtract(um, one)
	b := new(field.Element).Add(um, one)
	// The sign bit of the encoding is always 0 because Bytes returns the
	// canonical encoding of y < p.
	y := new(field.Element).Multiply(a, b.Invert(b)).Bytes()

	return (&edwards25519.Point{}).SetBytes(y)
}

// isReduced reports whether u is the canonical encoding of a field element,
// that is, u < p when read as a 256-bit little-endian integer, which also
// excludes the encodings with the most significant bit set.
func isReduced(u []byte) bool {
	e, err := (&field.Element{}).SetBytes(u)
	return err == nil && bytes.Equal(e.Bytes(), u)
}
