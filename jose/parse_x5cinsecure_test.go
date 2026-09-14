package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// signWithX5cInsecure mints a token carrying the given x5cInsecure header value.
func signWithX5cInsecure(t *testing.T, value any) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	opts := new(SignerOptions).WithType("JWT")
	opts.ExtraHeaders = map[HeaderKey]any{HeaderKey(X5cInsecureKey): value}

	signer, err := NewSigner(SigningKey{Algorithm: ES256, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := Signed(signer).Claims(map[string]any{"sub": "test"}).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// An x5cInsecure header holding an empty list decodes to an empty chain with no
// error, so the leaf lookup used to run off the front of the slice.
func TestParseX5cInsecureEmptyChain(t *testing.T) {
	tok := signWithX5cInsecure(t, []any{})

	jwt, chains, err := ParseX5cInsecure(tok, nil)
	if err == nil {
		t.Fatalf("expected an error for an empty x5cInsecure chain, got jwt=%v chains=%v", jwt, chains)
	}
	t.Logf("got error: %v", err)
}
