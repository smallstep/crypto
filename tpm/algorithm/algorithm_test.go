package algorithm

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

func Test_AlgorithmString(t *testing.T) {
	tests := []struct {
		name string
		id   tpm2.Algorithm
		want string
	}{
		{"ok/RSA", tpm2.AlgRSA, "RSA"},
		{"ok/3DES", 0x0003, "3DES"},
		{"ok/UNKNOWN", math.MaxUint16, "UNKNOWN_ALGORITHM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Algorithm(tt.id).String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_AlgorithmMarshalJSON(t *testing.T) {
	b, err := json.Marshal(Algorithm(tpm2.AlgRSA))
	require.NoError(t, err)
	require.JSONEq(t, `"RSA"`, string(b))
}
