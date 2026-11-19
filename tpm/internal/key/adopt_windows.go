//go:build windows

package key

import (
	"crypto"
	"fmt"
	"unsafe"

	"github.com/google/go-tpm/legacy/tpm2"
	"golang.org/x/sys/windows"
)

func adopt(keyName string, config AdoptConfig) ([]byte, crypto.PublicKey, error) {
	pcp, err := openPCP()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open PCP: %w", err)
	}
	defer pcp.Close()

	kh, err := pcp.openKey(keyName, config.MachineKey)
	if err != nil {
		return nil, nil, err
	}
	defer closeNCryptObject(kh) //nolint:errcheck // nothing to do about a handle that fails to close

	blob, err := exportOpaqueKeyBlob(kh)
	if err != nil {
		return nil, nil, err
	}
	pub, _, err := decodeKeyBlob(blob)
	if err != nil {
		return nil, nil, fmt.Errorf("decodeKeyBlob failed: %w", err)
	}

	tpmPub, err := tpm2.DecodePublic(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed decoding the public area of key %q: %w", keyName, err)
	}
	if err := CheckAdoptable(tpmPub); err != nil {
		return nil, nil, fmt.Errorf("key %q cannot be adopted: %w", keyName, err)
	}
	pubKey, err := tpmPub.Key()
	if err != nil {
		return nil, nil, fmt.Errorf("failed reading the public key of key %q: %w", keyName, err)
	}

	out := serializedKey{
		Encoding:   keyEncodingOSManaged,
		TPMVersion: uint8(2), // hardcoded to not import github.com/google/go-attestation/attest
		Name:       keyName,
		Public:     pub,
	}
	data, err := out.Serialize()
	if err != nil {
		return nil, nil, err
	}

	return data, pubKey, nil
}

// openKey opens the key persisted under name, in the machine key store when
// machineKey is set and in the current user's otherwise.
func (h *winPCP) openKey(name string, machineKey bool) (uintptr, error) {
	utf16Name, err := windows.UTF16FromString(name)
	if err != nil {
		return 0, err
	}

	var flags uint32
	if machineKey {
		flags = ncryptMachineKeyFlag
	}

	var kh uintptr
	r, _, msg := nCryptOpenKey.Call(h.hProv, uintptr(unsafe.Pointer(&kh)), uintptr(unsafe.Pointer(&utf16Name[0])), 0, uintptr(flags))
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return 0, fmt.Errorf("NCryptOpenKey returned 0x%X: %v", r, msg)
	}

	return kh, nil
}

// exportOpaqueKeyBlob exports the PCP_KEY_BLOB of an open key, the same blob
// newKey reads the public area of a key it creates from.
func exportOpaqueKeyBlob(kh uintptr) ([]byte, error) {
	typeString, err := windows.UTF16FromString("OpaqueKeyBlob")
	if err != nil {
		return nil, err
	}

	var sz uint32
	if r, _, msg := nCryptExportKey.Call(kh, 0, uintptr(unsafe.Pointer(&typeString[0])), 0, 0, 0, uintptr(unsafe.Pointer(&sz)), 0); r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, fmt.Errorf("NCryptExportKey returned 0x%X querying the key blob size: %v", r, msg)
	}

	blob := make([]byte, sz)
	if r, _, msg := nCryptExportKey.Call(kh, 0, uintptr(unsafe.Pointer(&typeString[0])), 0, uintptr(unsafe.Pointer(&blob[0])), uintptr(sz), uintptr(unsafe.Pointer(&sz)), 0); r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, fmt.Errorf("NCryptExportKey returned 0x%X exporting the key blob: %v", r, msg)
	}

	return blob[:sz], nil
}
