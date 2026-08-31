//go:build !go1.27

package x509util

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSignatureAlgorithm_MLDSA_unsupported verifies that ML-DSA signature
// algorithm names are not recognized on Go toolchains older than 1.27.
func TestSignatureAlgorithm_MLDSA_unsupported(t *testing.T) {
	for _, name := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		var sa SignatureAlgorithm
		err := json.Unmarshal([]byte(`"`+name+`"`), &sa)
		require.Error(t, err)
	}
}
