// CODE COPIED FROM github.com/google/go-attestation; DO NOT EDIT!
//
// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

//go:build windows

//nolint:errorlint,revive // copied package https://github.com/google/go-attestation/blob/master/attest/pcp_windows.go
package key

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	pcpProviderName = "Microsoft Platform Crypto Provider"
	cryptENotFound  = 0x80092004 // From winerror.h.

	// The below is documented in this Microsoft whitepaper:
	// https://github.com/Microsoft/TSS.MSR/blob/master/PCPTool.v11/Using%20the%20Windows%208%20Platform%20Crypto%20Provider%20and%20Associated%20TPM%20Functionality.pdf
	ncryptOverwriteKeyFlag = 0x80
	// Key usage value for generic keys
	nCryptPropertyPCPKeyUsagePolicyGeneric = 0x3
	// Key usage value for AKs.
	nCryptPropertyPCPKeyUsagePolicyIdentity = 0x8

	// PCP key magic
	pcpKeyMagic = 0x4D504350

	// TPM types from PCP_KEY_BLOB header data
	tpm12 = 0x1
	tpm20 = 0x2
)

// DLL references.
var (
	nCrypt                    = windows.MustLoadDLL("ncrypt.dll")
	nCryptOpenStorageProvider = nCrypt.MustFindProc("NCryptOpenStorageProvider")
	nCryptFreeObject          = nCrypt.MustFindProc("NCryptFreeObject")
	nCryptGetProperty         = nCrypt.MustFindProc("NCryptGetProperty")
	nCryptSetProperty         = nCrypt.MustFindProc("NCryptSetProperty")
	nCryptOpenKey             = nCrypt.MustFindProc("NCryptOpenKey")
	nCryptCreatePersistedKey  = nCrypt.MustFindProc("NCryptCreatePersistedKey")
	nCryptFinalizeKey         = nCrypt.MustFindProc("NCryptFinalizeKey")
	nCryptDeleteKey           = nCrypt.MustFindProc("NCryptDeleteKey")
	nCryptExportKey           = nCrypt.MustFindProc("NCryptExportKey")

	crypt32                            = windows.MustLoadDLL("crypt32.dll")
	crypt32CertEnumCertificatesInStore = crypt32.MustFindProc("CertEnumCertificatesInStore")
	crypt32CertCloseStore              = crypt32.MustFindProc("CertCloseStore")

	tbs              *windows.DLL
	tbsGetDeviceInfo *windows.Proc
)

// Error codes.
var (
	isReadyErrors = map[uint32]string{
		0x00000002: "Platform restart is required (shutdown).",
		0x00000004: "Platform restart is required (reboot).",
		0x00000008: "The TPM is already owned.",
		0x00000010: "Physical presence is required to provision the TPM.",
		0x00000020: "The TPM is disabled or deactivated.",
		0x00000040: "TPM ownership was taken.",
		0x00000080: "An endorsement key exists in the TPM.",
		0x00000100: "The TPM owner authorization is not properly stored in the registry.",
		0x00000200: "The Storage Root Key (SRK) authorization value is not all zeros.",
		0x00000800: "The operating system's registry information about the TPM’s Storage Root Key does not match the TPM Storage Root Key.",
		0x00001000: "The TPM permanent flag to allow reading of the Storage Root Key public value is not set.",
		0x00002000: "The monotonic counter incremented during boot has not been created.",
		0x00020000: "Windows Group Policy is configured to not store any TPM owner authorization so the TPM cannot be fully ready.",
		0x00040000: "The EK Certificate was not read from the TPM NV Ram and stored in the registry.",
		0x00080000: "The TCG event log is empty or cannot be read.",
		0x00100000: "The TPM is not owned.",
		0x00200000: "An error occurred, but not specific to a particular task.",
		0x00400000: "The device lock counter has not been created.",
		0x00800000: "The device identifier has not been created.",
	}
	tpmErrNums = map[uint32]string{
		0x80280001: "TPM_E_AUTHFAIL",
		0x80280002: "TPM_E_BADINDEX",
		0x80280003: "TPM_E_BAD_PARAMETER",
		0x80280004: "TPM_E_AUDITFAILURE",
		0x80280005: "TPM_E_CLEAR_DISABLED",
		0x80280006: "TPM_E_DEACTIVATED",
		0x80280007: "TPM_E_DISABLED",
		0x80280008: "TPM_E_DISABLED_CMD",
		0x80280009: "TPM_E_FAIL",
		0x8028000A: "TPM_E_BAD_ORDINAL",
		0x8028000B: "TPM_E_INSTALL_DISABLED",
		0x8028000C: "TPM_E_INVALID_KEYHANDLE",
		0x8028000D: "TPM_E_KEYNOTFOUND",
		0x8028000E: "TPM_E_INAPPROPRIATE_ENC",
		0x8028000F: "TPM_E_MIGRATEFAIL",
		0x80280010: "TPM_E_INVALID_PCR_INFO",
		0x80280011: "TPM_E_NOSPACE",
		0x80280012: "TPM_E_NOSRK",
		0x80280013: "TPM_E_NOTSEALED_BLOB",
		0x80280014: "TPM_E_OWNER_SET",
		0x80280015: "TPM_E_RESOURCES",
		0x80280016: "TPM_E_SHORTRANDOM",
		0x80280017: "TPM_E_SIZE",
		0x80280018: "TPM_E_WRONGPCRVAL",
		0x80280019: "TPM_E_BAD_PARAM_SIZE",
		0x8028001A: "TPM_E_SHA_THREAD",
		0x8028001B: "TPM_E_SHA_ERROR",
		0x8028001C: "TPM_E_FAILEDSELFTEST",
		0x8028001D: "TPM_E_AUTH2FAIL",
		0x8028001E: "TPM_E_BADTAG",
		0x8028001F: "TPM_E_IOERROR",
		0x80280020: "TPM_E_ENCRYPT_ERROR",
		0x80280021: "TPM_E_DECRYPT_ERROR",
		0x80280022: "TPM_E_INVALID_AUTHHANDLE",
		0x80280023: "TPM_E_NO_ENDORSEMENT",
		0x80280024: "TPM_E_INVALID_KEYUSAGE",
		0x80280025: "TPM_E_WRONG_ENTITYTYPE",
		0x80280026: "TPM_E_INVALID_POSTINIT",
		0x80280027: "TPM_E_INAPPROPRIATE_SIG",
		0x80280028: "TPM_E_BAD_KEY_PROPERTY",
		0x80280029: "TPM_E_BAD_MIGRATION",
		0x8028002A: "TPM_E_BAD_SCHEME",
		0x8028002B: "TPM_E_BAD_DATASIZE",
		0x8028002C: "TPM_E_BAD_MODE",
		0x8028002D: "TPM_E_BAD_PRESENCE",
		0x8028002E: "TPM_E_BAD_VERSION",
		0x8028002F: "TPM_E_NO_WRAP_TRANSPORT",
		0x80280030: "TPM_E_AUDITFAIL_UNSUCCESSFUL",
		0x80280031: "TPM_E_AUDITFAIL_SUCCESSFUL",
		0x80280032: "TPM_E_NOTRESETABLE",
		0x80280033: "TPM_E_NOTLOCAL",
		0x80280034: "TPM_E_BAD_TYPE",
		0x80280035: "TPM_E_INVALID_RESOURCE",
		0x80280036: "TPM_E_NOTFIPS",
		0x80280037: "TPM_E_INVALID_FAMILY",
		0x80280038: "TPM_E_NO_NV_PERMISSION",
		0x80280039: "TPM_E_REQUIRES_SIGN",
		0x8028003A: "TPM_E_KEY_NOTSUPPORTED",
		0x8028003B: "TPM_E_AUTH_CONFLICT",
		0x8028003C: "TPM_E_AREA_LOCKED",
		// TODO: Finish NVRAM error codes.
		0x80280049: "TPM_E_NOOPERATOR",
		0x8028004A: "TPM_E_RESOURCEMISSING",
		0x8028004B: "TPM_E_DELEGATE_LOCK",
		0x8028004C: "TPM_E_DELEGATE_FAMILY",
		0x8028004D: "TPM_E_DELEGATE_ADMIN",
		0x8028004E: "TPM_E_TRANSPORT_NOTEXCLUSIVE",
		0x8028004F: "TPM_E_OWNER_CONTROL",
		0x80280050: "TPM_E_DAA_RESOURCES",
		// TODO: Finish DAA error codes.
		0x80280058: "TPM_E_BAD_HANDLE",
		0x80280059: "TPM_E_BAD_DELEGATE",
		0x8028005A: "TPM_E_BADCONTEXT",
		0x8028005B: "TPM_E_TOOMANYCONTEXTS",
		0x8028005C: "TPM_E_MA_TICKET_SIGNATURE",
		0x8028005D: "TPM_E_MA_DESTINATION",
		0x8028005E: "TPM_E_MA_SOURCE",
		0x8028005F: "TPM_E_MA_AUTHORITY",
		0x80280061: "TPM_E_PERMANENTEK",
		0x80280062: "TPM_E_BAD_SIGNATURE",
		0x80280063: "TPM_E_NOCONTEXTSPACE",
		0x80280400: "TPM_E_COMMAND_BLOCKED",
		0x80280401: "TPM_E_INVALID_HANDLE",
		0x80280402: "TPM_E_DUPLICATE_VHANDLE",
		0x80280403: "TPM_E_EMBEDDED_COMMAND_BLOCKED",
		0x80280404: "TPM_E_EMBEDDED_COMMAND_UNSUPPORTED",
		0x80280800: "TPM_E_RETRY",
		0x80280801: "TPM_E_NEEDS_SELFTEST",
		0x80280802: "TPM_E_DOING_SELFTEST",
		0x80280803: "TPM_E_DEFEND_LOCK_RUNNING",
		0x80284001: "TBS_E_INTERNAL_ERROR",
		0x80284002: "TBS_E_BAD_PARAMETER",
		0x80284003: "TBS_E_INVALID_OUTPUT_POINTER",
		0x80284004: "TBS_E_INVALID_CONTEXT",
		0x80284005: "TBS_E_INSUFFICIENT_BUFFER",
		0x80284006: "TBS_E_IOERROR",
		0x80284007: "TBS_E_INVALID_CONTEXT_PARAM",
		0x80284008: "TBS_E_SERVICE_NOT_RUNNING",
		0x80284009: "TBS_E_TOO_MANY_TBS_CONTEXTS",
		0x8028400A: "TBS_E_TOO_MANY_RESOURCES",
		0x8028400B: "TBS_E_SERVICE_START_PENDING",
		0x8028400C: "TBS_E_PPI_NOT_SUPPORTED",
		0x8028400D: "TBS_E_COMMAND_CANCELED",
		0x8028400E: "TBS_E_BUFFER_TOO_LARGE",
		0x8028400F: "TBS_E_TPM_NOT_FOUND",
		0x80284010: "TBS_E_SERVICE_DISABLED",
		0x80284011: "TBS_E_NO_EVENT_LOG",
		0x80284012: "TBS_E_ACCESS_DENIED",
		0x80284013: "TBS_E_PROVISIONING_NOT_ALLOWED",
		0x80284014: "TBS_E_PPI_FUNCTION_UNSUPPORTED",
		0x80284015: "TBS_E_OWNERAUTH_NOT_FOUND",
		0x80284016: "TBS_E_PROVISIONING_INCOMPLETE",
		// TODO: TPMAPI & TPMSIMP error codes.
		0x80290401: "TPM_E_PCP_DEVICE_NOT_READY",
		0x80290402: "TPM_E_PCP_INVALID_HANDLE",
		0x80290403: "TPM_E_PCP_INVALID_PARAMETER",
		0x80290404: "TPM_E_PCP_FLAG_NOT_SUPPORTED",
		0x80290405: "TPM_E_PCP_NOT_SUPPORTED",
		0x80290406: "TPM_E_PCP_BUFFER_TOO_SMALL",
		0x80290407: "TPM_E_PCP_INTERNAL_ERROR",
		0x80290408: "TPM_E_PCP_AUTHENTICATION_FAILED",
		0x80290409: "TPM_E_PCP_AUTHENTICATION_IGNORED",
		0x8029040A: "TPM_E_PCP_POLICY_NOT_FOUND",
		0x8029040B: "TPM_E_PCP_PROFILE_NOT_FOUND",
		0x8029040C: "TPM_E_PCP_VALIDATION_FAILED",
		0x80090009: "NTE_BAD_FLAGS",
		0x80090026: "NTE_INVALID_HANDLE",
		0x80090027: "NTE_INVALID_PARAMETER",
		0x80090029: "NTE_NOT_SUPPORTED",
	}
)

func maybeWinErr(errNo uintptr) error {
	if code, known := tpmErrNums[uint32(errNo)]; known {
		return fmt.Errorf("tpm or subsystem failure: %s", code)
	}
	return nil
}

func utf16ToString(buf []byte) (string, error) {
	b := make([]uint16, len(buf)/2)
	// LPCSTR (Windows' representation of utf16) is always little endian.
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &b); err != nil {
		return "", err
	}
	return windows.UTF16ToString(b), nil
}

// closeNCryptoObject is a helper to call NCryptFreeObject on a given handle.
func closeNCryptObject(hnd uintptr) error {
	r, _, msg := nCryptFreeObject.Call(hnd)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			return tpmErr
		}
		return fmt.Errorf("NCryptFreeObject returned %X: %v", r, msg)
	}
	return nil
}

// getNCryptBufferProperty is a helper to read a byte slice from a NCrypt handle property
// using NCryptGetProperty.
func getNCryptBufferProperty(hnd uintptr, field string) ([]byte, error) {
	var size uint32
	wideField, err := windows.UTF16FromString(field)
	if err != nil {
		return nil, err
	}

	r, _, msg := nCryptGetProperty.Call(hnd, uintptr(unsafe.Pointer(&wideField[0])), 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, fmt.Errorf("NCryptGetProperty returned %d,%X (%v) for key %q on size read", size, r, msg, field)
	}
	buff := make([]byte, size)
	r, _, msg = nCryptGetProperty.Call(hnd, uintptr(unsafe.Pointer(&wideField[0])), uintptr(unsafe.Pointer(&buff[0])), uintptr(size), uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return nil, fmt.Errorf("NCryptGetProperty returned %X (%v) for key %q on data read", r, msg, field)
	}
	return buff, nil
}

// winPCP represents a reference to the Platform Crypto Provider.
type winPCP struct {
	hProv uintptr
}

// Close releases all resources managed by the Handle.
func (h *winPCP) Close() error {
	return closeNCryptObject(h.hProv)
}

func (h *winPCP) newKey(name string, alg string, length uint32, policy uint32) (uintptr, []byte, []byte, error) {
	var kh uintptr
	utf16Name, err := windows.UTF16FromString(name)
	if err != nil {
		return 0, nil, nil, err
	}
	utf16RSA, err := windows.UTF16FromString(alg)
	if err != nil {
		return 0, nil, nil, err
	}

	// Create a persistent RSA key of the specified name.
	r, _, msg := nCryptCreatePersistedKey.Call(h.hProv, uintptr(unsafe.Pointer(&kh)), uintptr(unsafe.Pointer(&utf16RSA[0])), uintptr(unsafe.Pointer(&utf16Name[0])), 0, 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return 0, nil, nil, fmt.Errorf("NCryptCreatePersistedKey returned %X: %v", r, msg)
	}

	// Set the length if provided
	if length != 0 {
		utf16Length, err := windows.UTF16FromString("Length")
		if err != nil {
			return 0, nil, nil, err
		}
		r, _, msg = nCryptSetProperty.Call(kh, uintptr(unsafe.Pointer(&utf16Length[0])), uintptr(unsafe.Pointer(&length)), unsafe.Sizeof(length), 0)
		if r != 0 {
			if tpmErr := maybeWinErr(r); tpmErr != nil {
				msg = tpmErr
			}
			return 0, nil, nil, fmt.Errorf("NCryptSetProperty (Length) returned %X: %v", r, msg)
		}
	}
	// Specify the generated key usage policy if appropriate
	if policy != 0 {
		utf16KeyPolicy, err := windows.UTF16FromString("PCP_KEY_USAGE_POLICY")
		if err != nil {
			return 0, nil, nil, err
		}
		r, _, msg = nCryptSetProperty.Call(kh, uintptr(unsafe.Pointer(&utf16KeyPolicy[0])), uintptr(unsafe.Pointer(&policy)), unsafe.Sizeof(policy), 0)
		if r != 0 {
			if tpmErr := maybeWinErr(r); tpmErr != nil {
				msg = tpmErr
			}
			return 0, nil, nil, fmt.Errorf("NCryptSetProperty (PCP KeyUsage Policy) returned %X: %v", r, msg)
		}
	}

	// Finalize (create) the key.
	r, _, msg = nCryptFinalizeKey.Call(kh, 0)
	if r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			msg = tpmErr
		}
		return 0, nil, nil, fmt.Errorf("NCryptFinalizeKey returned %X: %v", r, msg)
	}

	// Obtain the key blob.
	var sz uint32
	typeString, err := windows.UTF16FromString("OpaqueKeyBlob")
	if err != nil {
		return 0, nil, nil, err
	}

	if r, _, err := nCryptExportKey.Call(kh, 0, uintptr(unsafe.Pointer(&typeString[0])), 0, 0, 0, uintptr(unsafe.Pointer(&sz)), 0); r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			err = tpmErr
		}
		return 0, nil, nil, fmt.Errorf("NCryptGetProperty for hKey blob original query returned %X (%v)", r, err)
	}

	keyBlob := make([]byte, sz)

	if r, _, err := nCryptExportKey.Call(kh, 0, uintptr(unsafe.Pointer(&typeString[0])), 0, uintptr(unsafe.Pointer(&keyBlob[0])), uintptr(sz), uintptr(unsafe.Pointer(&sz)), 0); r != 0 {
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			err = tpmErr
		}
		return 0, nil, nil, fmt.Errorf("NCryptGetProperty for hKey blob returned %X (%v)", r, err)
	}

	pubBlob, privBlob, err := decodeKeyBlob(keyBlob)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("decodeKeyBlob failed: %v", err)
	}

	return kh, pubBlob, privBlob, nil
}

// NewKey creates a persistent application key of the specified name.
func (h *winPCP) NewKey(name string, config *KeyConfig) (uintptr, []byte, []byte, error) {
	if config.Algorithm == RSA {
		return h.newKey(name, "RSA", uint32(config.Size), 0)
	} else if config.Algorithm == ECDSA {
		switch config.Size {
		case 256:
			return h.newKey(name, "ECDSA_P256", 0, 0)
		case 384:
			return h.newKey(name, "ECDSA_P384", 0, 0)
		case 521:
			return h.newKey(name, "ECDSA_P521", 0, 0)
		default:
			return 0, nil, nil, fmt.Errorf("unsupported ECDSA key size: %v", config.Size)
		}
	}
	return 0, nil, nil, fmt.Errorf("unsupported algorithm type: %q", config.Algorithm)
}

func decodeKeyBlob(keyBlob []byte) ([]byte, []byte, error) {
	r := bytes.NewReader(keyBlob)

	var magic uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return nil, nil, fmt.Errorf("failed to read header magic: %v", err)
	}
	if magic != pcpKeyMagic {
		return nil, nil, fmt.Errorf("invalid header magic %X", magic)
	}

	var headerSize uint32
	if err := binary.Read(r, binary.LittleEndian, &headerSize); err != nil {
		return nil, nil, fmt.Errorf("failed to read header size: %v", err)
	}

	var tpmType uint32
	if err := binary.Read(r, binary.LittleEndian, &tpmType); err != nil {
		return nil, nil, fmt.Errorf("failed to read tpm type: %v", err)
	}

	if tpmType == tpm12 {
		return nil, nil, fmt.Errorf("TPM 1.2 currently unsupported")
	}

	var flags uint32
	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return nil, nil, fmt.Errorf("failed to read key flags: %v", err)
	}

	var pubLen uint32
	if err := binary.Read(r, binary.LittleEndian, &pubLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read length of public key: %v", err)
	}

	var privLen uint32
	if err := binary.Read(r, binary.LittleEndian, &privLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read length of private blob: %v", err)
	}

	var pubMigrationLen uint32
	if err := binary.Read(r, binary.LittleEndian, &pubMigrationLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read length of public migration blob: %v", err)
	}

	var privMigrationLen uint32
	if err := binary.Read(r, binary.LittleEndian, &privMigrationLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read length of private migration blob: %v", err)
	}

	var policyDigestLen uint32
	if err := binary.Read(r, binary.LittleEndian, &policyDigestLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read length of policy digest: %v", err)
	}

	var pcrBindingLen uint32
	if err := binary.Read(r, binary.LittleEndian, &pcrBindingLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read length of PCR binding: %v", err)
	}

	var pcrDigestLen uint32
	if err := binary.Read(r, binary.LittleEndian, &pcrDigestLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read length of PCR digest: %v", err)
	}

	var encryptedSecretLen uint32
	if err := binary.Read(r, binary.LittleEndian, &encryptedSecretLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read length of hostage import symmetric key: %v", err)
	}

	var tpm12HostageLen uint32
	if err := binary.Read(r, binary.LittleEndian, &tpm12HostageLen); err != nil {
		return nil, nil, fmt.Errorf("failed to read length of hostage import private key: %v", err)
	}

	// Skip over any padding
	r.Seek(int64(headerSize), 0)

	pubKey := make([]byte, pubLen)

	if err := binary.Read(r, binary.BigEndian, &pubKey); err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %v", err)
	}

	privBlob := make([]byte, privLen)
	if err := binary.Read(r, binary.BigEndian, &privBlob); err != nil {
		return nil, nil, fmt.Errorf("failed to read private blob: %v", err)
	}

	return pubKey[2:], privBlob[2:], nil
}

// openPCP initializes a reference to the Microsoft PCP provider.
// The Caller is expected to call Close() when they are done.
func openPCP() (*winPCP, error) {
	var err error
	var h winPCP
	pname, err := windows.UTF16FromString(pcpProviderName)
	if err != nil {
		return nil, err
	}

	r, _, err := nCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h.hProv)), uintptr(unsafe.Pointer(&pname[0])), 0)
	if r != 0 { // r is non-zero on error, err is always populated in this case.
		if tpmErr := maybeWinErr(r); tpmErr != nil {
			return nil, tpmErr
		}
		return nil, err
	}
	return &h, nil
}
