package manufacturer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_GetEncodings(t *testing.T) {
	tests := []struct {
		name string
		id   ID
		want string
	}{
		{"infineon", 1229346816, "IFX"},
		{"intel", 1229870147, "INTC"},
		{"stm", 1398033696, "STM "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := GetEncodings(tt.id); got != tt.want {
				t.Errorf("GetEncodings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetNameByASCII(t *testing.T) {
	tests := []struct {
		name  string
		ascii string
		want  string
	}{
		{"infineon", "IFX", "Infineon"},
		{"intel", "INTC", "Intel"},
		{"stm", "STM ", "ST Microelectronics"},
		{"unknown", "0000", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetNameByASCII(tt.ascii); got != tt.want {
				t.Errorf("GetNameByASCII() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestID_MarshalJSON(t *testing.T) {
	b, err := json.Marshal(ID(12345678))
	require.NoError(t, err)
	require.JSONEq(t, `"12345678"`, string(b))
}
