//go:build windows
// +build windows

package capi

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

const (

	// Key storage properties
	NCRYPT_ALGORITHM_GROUP_PROPERTY = "Algorithm Group"
	NCRYPT_LENGTH_PROPERTY          = "Length"
	NCRYPT_KEY_TYPE_PROPERTY        = "Key Type"
	NCRYPT_UNIQUE_NAME_PROPERTY     = "Unique Name"
	NCRYPT_ECC_CURVE_NAME_PROPERTY  = "ECCCurveName"
	NCRYPT_IMPL_TYPE_PROPERTY       = "Impl Type"
	NCRYPT_PROV_HANDLE              = "Provider Handle"
	NCRYPT_PIN_PROPERTY             = "SmartCardPin"
	NCRYPT_SECURE_PIN_PROPERTY      = "SmartCardSecurePin"
	NCRYPT_READER_PROPERTY          = "SmartCardReader"

	// Key Storage Flags
	NCRYPT_MACHINE_KEY_FLAG = 0x00000001

	// Errors
	NTE_NOT_SUPPORTED         = uint32(0x80090029)
	NTE_INVALID_PARAMETER     = uint32(0x80090027)
	NTE_BAD_FLAGS             = uint32(0x80090009)
	NTE_NO_MORE_ITEMS         = uint32(0x8009002A)
	NTE_BAD_KEYSET            = uint32(0x80090016)
	SCARD_W_CANCELLED_BY_USER = uint32(0x8010006E)

	// wincrypt.h constants
	acquireCached           = 0x1                                             // CRYPT_ACQUIRE_CACHE_FLAG
	acquireSilent           = 0x40                                            // CRYPT_ACQUIRE_SILENT_FLAG
	encodingX509ASN         = 1                                               // X509_ASN_ENCODING
	encodingPKCS7           = 65536                                           // PKCS_7_ASN_ENCODING
	certStoreProvSystem     = 10                                              // CERT_STORE_PROV_SYSTEM
	certStoreOpenExisting   = 0x00004000                                      // CERT_STORE_OPEN_EXISTING_FLAG
	certStoreCurrentUser    = uint32(certStoreCurrentUserID << compareShift)  // CERT_SYSTEM_STORE_CURRENT_USER
	certStoreLocalMachine   = uint32(certStoreLocalMachineID << compareShift) // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certStoreCurrentUserID  = 1                                               // CERT_SYSTEM_STORE_CURRENT_USER_ID
	certStoreLocalMachineID = 2                                               // CERT_SYSTEM_STORE_LOCAL_MACHINE_ID
	infoIssuerFlag          = 4                                               // CERT_INFO_ISSUER_FLAG
	compareNameStrW         = 8                                               // CERT_COMPARE_NAME_STR_A
	compareShift            = 16                                              // CERT_COMPARE_SHIFT
	compareSHA1Hash         = 1                                               // CERT_COMPARE_SHA1_HASH
	findIssuerStr           = compareNameStrW<<compareShift | infoIssuerFlag  // CERT_FIND_ISSUER_STR_W
	findHash                = compareSHA1Hash << compareShift                 // CERT_FIND_HASH
	signatureKeyUsage       = 0x80                                            // CERT_DIGITAL_SIGNATURE_KEY_USAGE
	ncryptKeySpec           = 0xFFFFFFFF                                      // CERT_NCRYPT_KEY_SPEC

	BCRYPT_RSAPUBLIC_BLOB = "RSAPUBLICBLOB"
	BCRYPT_ECCPUBLIC_BLOB = "ECCPUBLICBLOB"

	// winerror.h constants
	CRYPT_E_NOT_FOUND                    = uint32(0x80092004)
	CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG  = uint32(0x00010000)
	CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = uint32(0x00020000)
	CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG   = uint32(0x00040000)

	AT_KEYEXCHANGE = uint32(1)
	AT_SIGNATURE   = uint32(2)

	// Legacy CryptoAPI flags
	bCryptPadPKCS1 = uint32(2)

	// Magic numbers for public key blobs.
	rsa1Magic = 0x31415352 // "RSA1" BCRYPT_RSAPUBLIC_MAGIC
	ecs1Magic = 0x31534345 // "ECS1" BCRYPT_ECDSA_PUBLIC_P256_MAGIC
	ecs3Magic = 0x33534345 // "ECS3" BCRYPT_ECDSA_PUBLIC_P384_MAGIC
	ecs5Magic = 0x35534345 // "ECS5" BCRYPT_ECDSA_PUBLIC_P521_MAGIC
)

var (
	// curveNames maps bcrypt.h curve names to elliptic curves.
	curveNames = map[string]elliptic.Curve{
		"nistP256": elliptic.P256(), // BCRYPT_ECC_CURVE_NISTP256
		"nistP384": elliptic.P384(), // BCRYPT_ECC_CURVE_NISTP384
		"nistP521": elliptic.P521(), // BCRYPT_ECC_CURVE_NISTP521
	}

	curveMagicMap = map[string]uint32{
		"P-256": ecs1Magic,
		"P-384": ecs3Magic,
		"P-521": ecs5Magic,
	}

	// algIDs maps crypto.Hash values to bcrypt.h constants.
	hashAlgorithms = map[crypto.Hash]string{
		crypto.SHA1:   "SHA1",   // BCRYPT_SHA1_ALGORITHM
		crypto.SHA256: "SHA256", // BCRYPT_SHA256_ALGORITHM
		crypto.SHA384: "SHA384", // BCRYPT_SHA384_ALGORITHM
		crypto.SHA512: "SHA512", // BCRYPT_SHA512_ALGORITHM
	}

	crypt32 = windows.MustLoadDLL("crypt32.dll")
	nCrypt  = windows.MustLoadDLL("ncrypt.dll")

	certFindCertificateInStore      = crypt32.MustFindProc("CertFindCertificateInStore")
	cryptFindCertificateKeyProvInfo = crypt32.MustFindProc("CryptFindCertificateKeyProvInfo")
	nCryptCreatePersistedKey        = nCrypt.MustFindProc("NCryptCreatePersistedKey")
	nCryptExportKey                 = nCrypt.MustFindProc("NCryptExportKey")
	nCryptFinalizeKey               = nCrypt.MustFindProc("NCryptFinalizeKey")
	nCryptFreeObject                = nCrypt.MustFindProc("NCryptFreeObject")
	nCryptOpenKey                   = nCrypt.MustFindProc("NCryptOpenKey")
	nCryptOpenStorageProvider       = nCrypt.MustFindProc("NCryptOpenStorageProvider")
	nCryptGetProperty               = nCrypt.MustFindProc("NCryptGetProperty")
	nCryptSetProperty               = nCrypt.MustFindProc("NCryptSetProperty")
	nCryptSignHash                  = nCrypt.MustFindProc("NCryptSignHash")
)

type BCRYPT_PKCS1_PADDING_INFO struct {
	pszAlgID *uint16
}

func errNoToStr(e uint32) string {
	switch e {
	case NTE_INVALID_PARAMETER:
		return "NTE_INVALID_PARAMETER"
	case NTE_BAD_FLAGS:
		return "NTE_BAD_FLAGS"
	case NTE_BAD_KEYSET:
		return "NTE_BAD_KEYSET"
	case NTE_NO_MORE_ITEMS:
		return "NTE_NO_MORE_ITEMS"
	case NTE_NOT_SUPPORTED:
		return "NTE_NOT_SUPPORTED"
	case SCARD_W_CANCELLED_BY_USER:
		return "User cancelled smartcard action"
	default:
		return fmt.Sprintf("0x%X", e)
	}
}

// wide returns a pointer to a a uint16 representing the equivalent
// to a Windows LPCWSTR.
func wide(s string) *uint16 {
	w, _ := syscall.UTF16PtrFromString(s)
	return w
}

func NCryptOpenStorage(provider string) (uintptr, error) {
	var hProv uintptr
	// Open the provider, the last parameter is not used
	r, _, err := nCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProv)),
		uintptr(unsafe.Pointer(wide(provider))),
		0)
	if r == 0 {
		return hProv, nil
	}
	return hProv, fmt.Errorf("NCryptOpenStorageProvider returned %v: %v", errNoToStr(uint32(r)), err)
}

func NCryptFreeObject(h uintptr) error {
	r, _, err := nCryptFreeObject.Call(h)
	if r == 0 {
		return nil
	}
	return fmt.Errorf("NCryptFreeObject returned %v: %v", errNoToStr(uint32(r)), err)
}

func NCryptCreatePersistedKey(provisionerHandle uintptr, containerName string, algorithmName string, legacyKeySpec uint32, flags uint32) (uintptr, error) {

	var kh uintptr
	var kn uintptr = 0

	if containerName != "" {
		kn = uintptr(unsafe.Pointer(wide(containerName)))
	}

	r, _, err := nCryptCreatePersistedKey.Call(
		provisionerHandle,
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(wide(algorithmName))),
		kn,
		uintptr(legacyKeySpec),
		uintptr(flags))
	if r != 0 {
		return 0, fmt.Errorf("NCryptCreatePersistedKey returned %v: %v", errNoToStr(uint32(r)), err)
	}

	return kh, nil
}

func NCryptOpenKey(provisionerHandle uintptr, containerName string, legacyKeySpec uint32, flags uint32) (uintptr, error) {
	var kh uintptr
	r, _, err := nCryptOpenKey.Call(
		provisionerHandle,
		uintptr(unsafe.Pointer(&kh)),
		uintptr(unsafe.Pointer(wide(containerName))),
		uintptr(legacyKeySpec),
		uintptr(flags))
	if r != 0 {
		return 0, fmt.Errorf("NCryptOpenKey for container %q returned %v: %v", containerName, errNoToStr(uint32(r)), err)
	}

	return kh, nil
}

func NCryptFinalizeKey(keyHandle uintptr, flags uint32) error {
	r, _, err := nCryptFinalizeKey.Call(keyHandle, uintptr(flags))
	if r != 0 {
		return fmt.Errorf("NCryptFinalizeKey returned %v: %v", errNoToStr(uint32(r)), err)
	}

	return nil
}

func NCryptSetProperty(keyHandle uintptr, propertyName string, propertyValue interface{}, flags uint32) error {

	intVal, isInt := propertyValue.(uint32)

	if isInt {
		r, _, err := nCryptSetProperty.Call(
			keyHandle,
			uintptr(unsafe.Pointer(wide(propertyName))),
			uintptr(unsafe.Pointer(&intVal)),
			unsafe.Sizeof(intVal),
			uintptr(flags))
		if r != 0 {
			return fmt.Errorf("NCryptSetProperty \"%v\" returned %v: %v", propertyName, errNoToStr(uint32(r)), err)
		}

		return nil
	}

	strVal, isStr := propertyValue.(string)

	if isStr {
		l := len(strVal)

		r, _, err := nCryptSetProperty.Call(
			keyHandle,
			uintptr(unsafe.Pointer(wide(propertyName))),
			uintptr(unsafe.Pointer(wide(strVal))),
			uintptr(l),
			uintptr(flags))
		if r != 0 {
			return fmt.Errorf("NCryptSetProperty \"%v\" returned %X: %v", propertyName, errNoToStr(uint32(r)), err)
		}

		return nil
	}

	return fmt.Errorf("NCryptSetProperty %v invalid value", propertyName)
}

func NCryptSignHash(kh uintptr, digest []byte, hashID string) ([]byte, error) {
	var size uint32
	var padInfoPtr uintptr
	var flags uint32
	if hashID != "" {
		padInfo := BCRYPT_PKCS1_PADDING_INFO{pszAlgID: wide(hashID)}
		padInfoPtr = uintptr(unsafe.Pointer(&padInfo))
		flags = bCryptPadPKCS1
	} else {
		padInfoPtr = 0
		flags = 0
	}

	// Obtain the size of the signature
	r, _, err := nCryptSignHash.Call(
		kh,
		padInfoPtr,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags))
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %v during size check: %v", errNoToStr(uint32(r)), err)
	}

	// Obtain the signature data
	buf := make([]byte, size)
	r, _, err = nCryptSignHash.Call(
		kh,
		padInfoPtr,
		uintptr(unsafe.Pointer(&digest[0])),
		uintptr(len(digest)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		uintptr(flags),
	)
	if r != 0 {
		return nil, fmt.Errorf("NCryptSignHash returned %v during signing: %v", errNoToStr(uint32(r)), err)
	}

	return buf[:size], nil
}

func getProperty(kh uintptr, property *uint16) ([]byte, error) {
	var strSize uint32
	r, _, err := nCryptGetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(property)),
		0,
		0,
		uintptr(unsafe.Pointer(&strSize)),
		0,
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptGetProperty(%v) returned %v during size check: %v", property, errNoToStr(uint32(r)), err)
	}

	buf := make([]byte, strSize)
	r, _, err = nCryptGetProperty.Call(
		kh,
		uintptr(unsafe.Pointer(property)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(strSize),
		uintptr(unsafe.Pointer(&strSize)),
		0,
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptGetProperty %v returned %v during export: %v", property, errNoToStr(uint32(r)), err)
	}

	return buf, nil
}

func NCryptGetPropertyHandle(kh uintptr, property *uint16) (uintptr, error) {
	buf, err := getProperty(kh, property)
	if err != nil {
		return 0, err
	}
	if len(buf) < 1 {
		return 0, fmt.Errorf("empty result")
	}
	return **(**uintptr)(unsafe.Pointer(&buf)), nil
}

func NCryptGetPropertyInt(kh uintptr, property *uint16) (int, error) {
	buf, err := getProperty(kh, property)
	if err != nil {
		return 0, err
	}
	if len(buf) < 1 {
		return 0, fmt.Errorf("empty result")
	}
	return **(**int)(unsafe.Pointer(&buf)), nil
}

func NCryptGetPropertyStr(kh uintptr, property string) (string, error) {
	buf, err := getProperty(kh, wide(property))
	if err != nil {
		return "", err
	}
	uc := bytes.ReplaceAll(buf, []byte{0x00}, []byte(""))
	return string(uc), nil
}

func NCryptExportKey(kh uintptr, blobType string) ([]byte, error) {
	var size uint32
	// When obtaining the size of a public key, most parameters are not required
	r, _, err := nCryptExportKey.Call(
		kh,
		0,
		uintptr(unsafe.Pointer(wide(blobType))),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey returned %v during size check: %v", errNoToStr(uint32(r)), err)
	}

	// Place the exported key in buf now that we know the size required
	buf := make([]byte, size)
	r, _, err = nCryptExportKey.Call(
		kh,
		0,
		uintptr(unsafe.Pointer(wide(blobType))),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(unsafe.Pointer(&size)),
		0)
	if r != 0 {
		return nil, fmt.Errorf("NCryptExportKey returned %v during export: %v", errNoToStr(uint32(r)), err)
	}
	return buf, nil
}

func FindCertificateInStore(store windows.Handle, enc, findFlags, findType uint32, para uintptr, prev *windows.CertContext) (*windows.CertContext, error) {
	h, _, err := certFindCertificateInStore.Call(
		uintptr(store),
		uintptr(enc),
		uintptr(findFlags),
		uintptr(findType),
		para,
		uintptr(unsafe.Pointer(prev)),
	)
	if h == 0 {
		// Actual error, or simply not found?
		if errno, ok := err.(syscall.Errno); ok && uint32(errno) == CRYPT_E_NOT_FOUND {
			return nil, nil
		}
		return nil, err
	}
	return (*windows.CertContext)(unsafe.Pointer(h)), nil
}

func FreeCertContext(ctx *windows.CertContext) error {
	return windows.CertFreeCertificateContext(ctx)
}

func CryptFindCertificateKeyProvInfo(certContext *windows.CertContext) error {

	r, _, err := cryptFindCertificateKeyProvInfo.Call(
		uintptr(unsafe.Pointer(certContext)),
		uintptr(CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG),
		0,
	)

	if r == 0 {
		return fmt.Errorf("private key association failed: %v", err)
	}

	return nil
}
