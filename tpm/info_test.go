package tpm

import (
	"encoding/json"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/tpm/manufacturer"
)

func TestInterface_MarshalJSON(t *testing.T) {
	b, err := json.Marshal(Interface(attest.TPMInterfaceDirect))
	require.NoError(t, err)
	require.JSONEq(t, `"direct"`, string(b))

	b, err = json.Marshal(Interface(attest.TPMInterfaceKernelManaged))
	require.NoError(t, err)
	require.JSONEq(t, `"kernel-managed"`, string(b))

	b, err = json.Marshal(Interface(attest.TPMInterfaceDaemonManaged))
	require.NoError(t, err)
	require.JSONEq(t, `"daemon-managed"`, string(b))

	b, err = json.Marshal(Interface(attest.TPMInterfaceCommandChannel))
	require.NoError(t, err)
	require.JSONEq(t, `"command-channel"`, string(b))

	b, err = json.Marshal(Interface(255))
	require.NoError(t, err)
	require.JSONEq(t, `"unknown (255)"`, string(b))
}

func TestFirmwareVersion_MarshalJSON(t *testing.T) {
	b, err := json.Marshal(FirmwareVersion{Major: 0, Minor: 0})
	require.NoError(t, err)
	require.JSONEq(t, `"0.0"`, string(b))

	b, err = json.Marshal(FirmwareVersion{Major: 13, Minor: 37})
	require.NoError(t, err)
	require.JSONEq(t, `"13.37"`, string(b))
}

func TestVersion_MarshalJSON(t *testing.T) {
	b, err := json.Marshal(Version(attest.TPMVersion12))
	require.NoError(t, err)
	require.JSONEq(t, `"1.2"`, string(b))

	b, err = json.Marshal(Version(attest.TPMVersion20))
	require.NoError(t, err)
	require.JSONEq(t, `"2.0"`, string(b))

	b, err = json.Marshal(Version(0))
	require.NoError(t, err)
	require.JSONEq(t, `"unknown (0)"`, string(b))
}

func TestVersion_String(t *testing.T) {
	require.Equal(t, "TPM 1.2", Version(attest.TPMVersion12).String())
	require.Equal(t, "TPM 2.0", Version(attest.TPMVersion20).String())
	require.Equal(t, "unknown (0)", Version(0).String())
}

func Test_GetManufacturerByID(t *testing.T) {
	tests := []struct {
		name string
		id   manufacturer.ID
		want Manufacturer
	}{
		{"infineon", 1229346816, Manufacturer{1229346816, "Infineon", "IFX", "49465800"}},
		{"intel", 1229870147, Manufacturer{1229870147, "Intel", "INTC", "494E5443"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetManufacturerByID(tt.id); got != tt.want {
				t.Errorf("getManufacturerByID() = %v, want %v", got, tt.want)
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

func TestID_MarshalJSON(t *testing.T) {
	e := Manufacturer{}
	b, err := json.Marshal(e)
	require.NoError(t, err)
	require.JSONEq(t, `{"ascii":"", "hex":"", "id":"0", "name":""}`, string(b))

	m := Manufacturer{1229346816, "Infineon", "IFX", "49465800"}
	b, err = json.Marshal(m)
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"1229346816", "name":"Infineon", "ascii":"IFX", "hex":"49465800"}`, string(b))
}
