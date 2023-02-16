package tpm

import (
	"encoding/json"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/stretchr/testify/require"
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
	require.JSONEq(t, `"unknown"`, string(b))
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
	require.JSONEq(t, `"unknown"`, string(b))
}

func TestVersion_String(t *testing.T) {
	require.Equal(t, "TPM 1.2", Version(attest.TPMVersion12).String())
	require.Equal(t, "TPM 2.0", Version(attest.TPMVersion20).String())
	require.Equal(t, "unknown", Version(0).String())
}
