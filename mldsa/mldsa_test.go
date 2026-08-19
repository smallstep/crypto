package mldsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParametersByName(t *testing.T) {
	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"ML-DSA-44", "ML-DSA-44", false},
		{"ML-DSA-65", "ML-DSA-65", false},
		{"ML-DSA-87", "ML-DSA-87", false},
		{"ml-dsa-65", "ML-DSA-65", false}, // case-insensitive
		{"ML-DSA-99", "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := ParametersByName(tt.name)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, params.String())
		})
	}
}
