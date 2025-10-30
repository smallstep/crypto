package x509compat

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestRSAKeyParsing(t *testing.T) {
	// Generate RSA key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Test PKCS1 private key marshaling/parsing
	derPriv := MarshalPKCS1PrivateKey(priv)
	parsedPriv, err := ParsePKCS1PrivateKey(derPriv)
	if err != nil {
		t.Fatalf("Failed to parse PKCS1 private key: %v", err)
	}
	if parsedPriv.N.Cmp(priv.N) != 0 {
		t.Error("Parsed private key doesn't match original")
	}

	// Test PKCS1 public key marshaling/parsing
	derPub := MarshalPKCS1PublicKey(&priv.PublicKey)
	parsedPub, err := ParsePKCS1PublicKey(derPub)
	if err != nil {
		t.Fatalf("Failed to parse PKCS1 public key: %v", err)
	}
	if parsedPub.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("Parsed public key doesn't match original")
	}

	// Test PKCS8 marshaling/parsing
	derPKCS8, err := MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8 private key: %v", err)
	}
	parsedPKCS8, err := ParsePKCS8PrivateKey(derPKCS8)
	if err != nil {
		t.Fatalf("Failed to parse PKCS8 private key: %v", err)
	}
	rsaPKCS8, ok := parsedPKCS8.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("Parsed PKCS8 key is not *rsa.PrivateKey")
	}
	if rsaPKCS8.N.Cmp(priv.N) != 0 {
		t.Error("Parsed PKCS8 private key doesn't match original")
	}
}

func TestECDSAKeyParsing(t *testing.T) {
	// Generate ECDSA key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Test EC private key marshaling/parsing
	derPriv, err := MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal EC private key: %v", err)
	}
	parsedPriv, err := ParseECPrivateKey(derPriv)
	if err != nil {
		t.Fatalf("Failed to parse EC private key: %v", err)
	}
	if parsedPriv.D.Cmp(priv.D) != 0 {
		t.Error("Parsed EC private key doesn't match original")
	}

	// Test PKCS8 marshaling/parsing
	derPKCS8, err := MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8 private key: %v", err)
	}
	parsedPKCS8, err := ParsePKCS8PrivateKey(derPKCS8)
	if err != nil {
		t.Fatalf("Failed to parse PKCS8 private key: %v", err)
	}
	ecPKCS8, ok := parsedPKCS8.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Parsed PKCS8 key is not *ecdsa.PrivateKey")
	}
	if ecPKCS8.D.Cmp(priv.D) != 0 {
		t.Error("Parsed PKCS8 EC private key doesn't match original")
	}
}

func TestEd25519KeyParsing(t *testing.T) {
	// Generate Ed25519 key
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Test PKCS8 marshaling/parsing
	derPKCS8, err := MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS8 private key: %v", err)
	}
	parsedPKCS8, err := ParsePKCS8PrivateKey(derPKCS8)
	if err != nil {
		t.Fatalf("Failed to parse PKCS8 private key: %v", err)
	}
	ed25519PKCS8, ok := parsedPKCS8.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("Parsed PKCS8 key is not ed25519.PrivateKey")
	}
	if string(ed25519PKCS8) != string(priv) {
		t.Error("Parsed PKCS8 Ed25519 private key doesn't match original")
	}

	// Test PKIX public key marshaling/parsing
	derPub, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("Failed to marshal PKIX public key: %v", err)
	}
	parsedPub, err := ParsePKIXPublicKey(derPub)
	if err != nil {
		t.Fatalf("Failed to parse PKIX public key: %v", err)
	}
	ed25519Pub, ok := parsedPub.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Parsed PKIX key is not ed25519.PublicKey")
	}
	if string(ed25519Pub) != string(pub) {
		t.Error("Parsed PKIX Ed25519 public key doesn't match original")
	}
}

func TestPublicKeyAlgorithm(t *testing.T) {
	// Test RSA
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if algo := GetPublicKeyAlgorithm(&rsaKey.PublicKey); algo != RSA {
		t.Errorf("Expected RSA, got %v", algo)
	}
	if !IsRSA(&rsaKey.PublicKey) {
		t.Error("IsRSA returned false for RSA key")
	}

	// Test ECDSA
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if algo := GetPublicKeyAlgorithm(&ecKey.PublicKey); algo != ECDSA {
		t.Errorf("Expected ECDSA, got %v", algo)
	}
	if !IsECDSA(&ecKey.PublicKey) {
		t.Error("IsECDSA returned false for ECDSA key")
	}

	// Test Ed25519
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if algo := GetPublicKeyAlgorithm(edPub); algo != Ed25519 {
		t.Errorf("Expected Ed25519, got %v", algo)
	}
	if !IsEd25519(edPub) {
		t.Error("IsEd25519 returned false for Ed25519 key")
	}
}

func TestAlgorithmStrings(t *testing.T) {
	tests := []struct {
		algo PublicKeyAlgorithm
		want string
	}{
		{RSA, "RSA"},
		{DSA, "DSA"},
		{ECDSA, "ECDSA"},
		{Ed25519, "Ed25519"},
		{UnknownPublicKeyAlgorithm, "unknown public key algorithm"},
	}

	for _, tt := range tests {
		if got := tt.algo.String(); got != tt.want {
			t.Errorf("algo.String() = %q, want %q", got, tt.want)
		}
	}
}

func TestSignatureAlgorithmStrings(t *testing.T) {
	tests := []struct {
		algo SignatureAlgorithm
		want string
	}{
		{SHA256WithRSA, "SHA256-RSA"},
		{ECDSAWithSHA256, "ECDSA-SHA256"},
		{PureEd25519, "Ed25519"},
		{UnknownSignatureAlgorithm, "unknown signature algorithm"},
	}

	for _, tt := range tests {
		if got := tt.algo.String(); got != tt.want {
			t.Errorf("algo.String() = %q, want %q", got, tt.want)
		}
	}
}
