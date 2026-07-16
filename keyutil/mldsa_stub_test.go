//go:build !go1.27

package keyutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGenerateKey_MLDSA_unsupported verifies that requesting an ML-DSA key on a
// Go toolchain older than 1.27 returns an error instead of panicking.
func TestGenerateKey_MLDSA_unsupported(t *testing.T) {
	_, err := GenerateKey("MLDSA", "ML-DSA-65", 0)
	require.Error(t, err)

	_, err = GenerateSigner("MLDSA", "ML-DSA-65", 0)
	require.Error(t, err)
}
