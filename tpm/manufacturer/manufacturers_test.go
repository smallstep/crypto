package manufacturer

import (
	"testing"
)

func Test_getManufacturerEncodings(t *testing.T) {
	tests := []struct {
		name string
		id   ID
		want string
	}{
		{"infineon", 1229346816, "IFX"},
		{"intel", 1229870147, "INTC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := getManufacturerEncodings(tt.id); got != tt.want {
				t.Errorf("getManufacturerEncodings() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GetByID(t *testing.T) {
	tests := []struct {
		name string
		id   ID
		want Manufacturer
	}{
		{"infineon", 1229346816, Manufacturer{1229346816, "Infineon", "IFX", "49465800"}},
		{"intel", 1229870147, Manufacturer{1229870147, "Intel", "INTC", "494E5443"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetByID(tt.id); got != tt.want {
				t.Errorf("getManufacturerByID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getManufacturerNameByASCII(t *testing.T) {
	tests := []struct {
		name  string
		ascii string
		want  string
	}{
		{"infineon", "IFX", "Infineon"},
		{"intel", "INTC", "Intel"},
		{"unknown", "0000", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getManufacturerNameByASCII(tt.ascii); got != tt.want {
				t.Errorf("getManufacturerNameByASCII() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManufacturer_String(t *testing.T) {
	m := Manufacturer{
		Name:  "ST Microelectronics",
		ASCII: "STM",
		ID:    1398033696,
		Hex:   "53544D20",
	}
	want := "ST Microelectronics (STM, 53544D20, 1398033696)"
	if got := m.String(); got != want {
		t.Errorf("Manufacturer.String() = %v, want %v", got, want)
	}
}
