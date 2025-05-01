//go:build windows && !nocapi
// +build windows,!nocapi

package capi

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strings"
	"unsafe"

	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/randutil"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/sys/windows"
)

// Scheme is the scheme used in uris, the string "capi".
const Scheme = string(apiv1.CAPIKMS)

const (
	ProviderNameArg        = "provider"
	ContainerNameArg       = "key"
	HashArg                = "sha1"
	StoreLocationArg       = "store-location" // 'machine', 'user', etc
	StoreNameArg           = "store"          // 'MY', 'CA', 'ROOT', etc
	KeyIDArg               = "key-id"
	SubjectCNArg           = "cn"
	SerialNumberArg        = "serial"
	IssuerNameArg          = "issuer"
	KeySpec                = "key-spec"                  // 0, 1, 2; none/NONE, at_keyexchange/AT_KEYEXCHANGE, at_signature/AT_SIGNATURE
	SkipFindCertificateKey = "skip-find-certificate-key" // skips looking up certificate private key when storing a certificate
)

var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]string{
	apiv1.UnspecifiedSignAlgorithm: ALG_ECDSA_P256,
	apiv1.SHA256WithRSA:            ALG_RSA,
	apiv1.SHA384WithRSA:            ALG_RSA,
	apiv1.SHA512WithRSA:            ALG_RSA,
	apiv1.ECDSAWithSHA256:          ALG_ECDSA_P256,
	apiv1.ECDSAWithSHA384:          ALG_ECDSA_P384,
	apiv1.ECDSAWithSHA512:          ALG_ECDSA_P521,
}

// CAPIKMS implements a KMS using Windows CryptoAPI (CAPI) and Next-Gen CryptoAPI (CNG).
//
// The URI format used in CAPIKMS is the following:
//
//   - capi:provider=STORAGE-PROVIDER;key=KEY-NAME
//
// For certificates:
//   - capi:store-location=[machine|user];store=My;sha1=<THUMBPRINT>
//   - capi:store-location=[machine|user];store=My;key-id=<X509v3 Subject Key Identifier>
//   - capi:store-location=[machine|user];store=My;issuer=<Issuer CN>;serial=<Certificate SN>
//
// The scheme is "capi";
//
// "provider" is the provider name and can be one of:
// - "Microsoft Software Key Storage Provider"
// - "Microsoft Smart Card Key Storage Provider"
// - "Microsoft Platform Crypto Provider"
// if not set it defaults to "Microsoft Software Key Storage Provider"
//
// "key"              key container name. If not set one is generated.
// "store-location"   specifies the certificate store location - "user" or "machine"
// "store"            certificate store name - "My", "Root", and "CA" are some examples
// "sha1"             sha1 thumbprint of the certificate to load in hex format
// "key-id"           X509v3 Subject Key Identifier of the certificate to load in hex format
// "serial"           serial number of the certificate to load in hex format
// "issuer"           Common Name of the certificate issuer
// "key-spec"         the (legacy) KeySpec to use - 0, 1 or 2 (or none, at_keyexchange, at_signature)
type CAPIKMS struct {
	providerName   string
	providerHandle uintptr
	pin            string
}

func certContextToX509(certHandle *windows.CertContext) (*x509.Certificate, error) {
	var der []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&der))
	slice.Data = uintptr(unsafe.Pointer(certHandle.EncodedCert))
	slice.Len = int(certHandle.Length)
	slice.Cap = int(certHandle.Length)
	return x509.ParseCertificate(der)
}

func unmarshalRSA(buf []byte) (*rsa.PublicKey, error) {
	// BCRYPT_RSA_BLOB -- https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	header := struct {
		Magic         uint32
		BitLength     uint32
		PublicExpSize uint32
		ModulusSize   uint32
		UnusedPrime1  uint32
		UnusedPrime2  uint32
	}{}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	if header.Magic != rsa1Magic {
		return nil, fmt.Errorf("invalid header magic %x", header.Magic)
	}

	if header.PublicExpSize > 8 {
		return nil, fmt.Errorf("unsupported public exponent size (%d bits)", header.PublicExpSize*8)
	}

	// the exponent is in BigEndian format, so read the data into the right place in the buffer
	exp := make([]byte, 8)
	n, err := r.Read(exp[8-header.PublicExpSize:])

	if err != nil {
		return nil, fmt.Errorf("failed to read public exponent %w", err)
	}

	if n != int(header.PublicExpSize) {
		return nil, fmt.Errorf("failed to read correct public exponent size, read %d expected %d", n, int(header.PublicExpSize))
	}

	mod := make([]byte, header.ModulusSize)
	n, err = r.Read(mod)

	if err != nil {
		return nil, fmt.Errorf("failed to read modulus %w", err)
	}

	if n != int(header.ModulusSize) {
		return nil, fmt.Errorf("failed to read correct modulus size, read %d expected %d", n, int(header.ModulusSize))
	}

	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(mod),
		E: int(binary.BigEndian.Uint64(exp)),
	}
	return pub, nil
}

func unmarshalECC(buf []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	// BCRYPT_ECCKEY_BLOB -- https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
	header := struct {
		Magic uint32
		Key   uint32
	}{}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	if expectedMagic, ok := curveMagicMap[curve.Params().Name]; ok {
		if expectedMagic != header.Magic {
			return nil, fmt.Errorf("elliptic curve blob did not contain expected magic")
		}
	}

	keyX := make([]byte, header.Key)
	n, err := r.Read(keyX)
	if err != nil {
		return nil, fmt.Errorf("failed to read key X %w", err)
	}

	if n != int(header.Key) {
		return nil, fmt.Errorf("failed to read key X size, read %d expected %d", n, int(header.Key))
	}

	keyY := make([]byte, header.Key)
	n, err = r.Read(keyY)
	if err != nil {
		return nil, fmt.Errorf("failed to read key Y %w", err)
	}

	if n != int(header.Key) {
		return nil, fmt.Errorf("failed to read key Y size, read %d expected %d", n, int(header.Key))
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(keyX),
		Y:     new(big.Int).SetBytes(keyY),
	}
	return pub, nil
}

func getPublicKey(kh uintptr) (crypto.PublicKey, error) {
	algGroup, err := nCryptGetPropertyStr(kh, NCRYPT_ALGORITHM_GROUP_PROPERTY)
	if err != nil {
		return nil, fmt.Errorf("unable to get NCRYPT_ALGORITHM_GROUP_PROPERTY: %w", err)
	}

	var pub crypto.PublicKey
	switch algGroup {
	case "ECDSA":
		buf, err := nCryptExportKey(kh, BCRYPT_ECCPUBLIC_BLOB)
		if err != nil {
			return nil, fmt.Errorf("failed to export ECC public key: %w", err)
		}
		curveName, err := nCryptGetPropertyStr(kh, NCRYPT_ECC_CURVE_NAME_PROPERTY)
		if err != nil {
			// The smart card provider doesn't have the curve name property set, attempt to get it from
			// algorithm property
			curveName, err = nCryptGetPropertyStr(kh, NCRYPT_ALGORITHM_PROPERTY)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve ECC curve name: %w", err)
			}
		}

		if _, ok := curveNames[curveName]; !ok {
			return nil, fmt.Errorf("curveName %s not found in curvenames map", curveName)
		}
		pub, err = unmarshalECC(buf, curveNames[curveName])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ECC public key: %w", err)
		}
	case "RSA":
		buf, err := nCryptExportKey(kh, BCRYPT_RSAPUBLIC_BLOB)
		if err != nil {
			return nil, fmt.Errorf("failed to export %v public key: %w", algGroup, err)
		}
		pub, err = unmarshalRSA(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal %v public key: %w", algGroup, err)
		}
	default:
		return nil, fmt.Errorf("unhandled algorithm group %v retrieved from key", algGroup)
	}

	return pub, nil
}

// New returns a new CAPIKMS.
func New(ctx context.Context, opts apiv1.Options) (*CAPIKMS, error) {
	providerName := "Microsoft Software Key Storage Provider"
	pin := ""

	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, err
		}

		if v := u.Get(ProviderNameArg); v != "" {
			providerName = v
		}

		pin = u.Pin()
	}

	// TODO: a provider is not necessary for certificate functions, should we move this to the key and signing functions?
	ph, err := nCryptOpenStorageProvider(providerName)
	if err != nil {
		return nil, fmt.Errorf("could not open nCrypt provider: %w", err)
	}

	return &CAPIKMS{
		providerName:   providerName,
		providerHandle: ph,
		pin:            pin,
	}, nil
}

func init() {
	apiv1.Register(apiv1.CAPIKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

func (k *CAPIKMS) Close() error {
	if k.providerHandle != 0 {
		return nCryptFreeObject(k.providerHandle)
	}

	return nil
}

// getCertContext returns a pointer to a X.509 certificate context based on the provided URI
// callers are responsible for freeing the context
func (k *CAPIKMS) getCertContext(req *apiv1.LoadCertificateRequest) (*windows.CertContext, error) {
	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}

	sha1Hash, err := u.GetHexEncoded(HashArg)
	if err != nil {
		return nil, fmt.Errorf("failed getting %s from URI %q: %w", HashArg, req.Name, err)
	}
	keyID := u.Get(KeyIDArg)
	issuerName := u.Get(IssuerNameArg)
	subjectCN := u.Get(SubjectCNArg)
	serialNumber := u.Get(SerialNumberArg)

	// default to the user store
	var storeLocation string
	if storeLocation = u.Get(StoreLocationArg); storeLocation == "" {
		storeLocation = "user"
	}

	var certStoreLocation uint32
	switch storeLocation {
	case "user":
		certStoreLocation = certStoreCurrentUser
	case "machine":
		certStoreLocation = certStoreLocalMachine
	default:
		return nil, fmt.Errorf("invalid cert store location %q", storeLocation)
	}

	var storeName string

	// default to the 'My' store
	if storeName = u.Get(StoreNameArg); storeName == "" {
		storeName = "My"
	}

	st, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocation,
		uintptr(unsafe.Pointer(wide(storeName))))
	if err != nil {
		return nil, fmt.Errorf("CertOpenStore for the %q store %q returned: %w", storeLocation, storeName, err)
	}

	var handle *windows.CertContext

	switch {
	case len(sha1Hash) > 0:
		if len(sha1Hash) != 20 {
			return nil, fmt.Errorf("decoded %s has length %d; expected 20 bytes for SHA-1", HashArg, len(sha1Hash))
		}
		searchData := CERT_ID_KEYIDORHASH{
			idChoice: CERT_ID_SHA1_HASH,
			KeyIDOrHash: CRYPTOAPI_BLOB{
				len:  uint32(len(sha1Hash)),
				data: uintptr(unsafe.Pointer(&sha1Hash[0])),
			},
		}
		handle, err = findCertificateInStore(st,
			encodingX509ASN|encodingPKCS7,
			0,
			findCertID,
			uintptr(unsafe.Pointer(&searchData)), nil)
		if err != nil {
			return nil, fmt.Errorf("findCertificateInStore failed: %w", err)
		}
		if handle == nil {
			return nil, apiv1.NotFoundError{Message: fmt.Sprintf("certificate with %s=%s not found", HashArg, keyID)}
		}
	case keyID != "":
		keyID = strings.TrimPrefix(keyID, "0x") // Support specifying the hash as 0x like with serial

		keyIDBytes, err := hex.DecodeString(keyID)
		if err != nil {
			return nil, fmt.Errorf("%s must be in hex format: %w", KeyIDArg, err)
		}
		searchData := CERT_ID_KEYIDORHASH{
			idChoice: CERT_ID_KEY_IDENTIFIER,
			KeyIDOrHash: CRYPTOAPI_BLOB{
				len:  uint32(len(keyIDBytes)),
				data: uintptr(unsafe.Pointer(&keyIDBytes[0])),
			},
		}
		handle, err = findCertificateInStore(st,
			encodingX509ASN|encodingPKCS7,
			0,
			findCertID,
			uintptr(unsafe.Pointer(&searchData)), nil)
		if err != nil {
			return nil, fmt.Errorf("findCertificateInStore failed: %w", err)
		}
		if handle == nil {
			return nil, apiv1.NotFoundError{Message: fmt.Sprintf("certificate with %s=%s not found", KeyIDArg, keyID)}
		}
	case issuerName != "" && (serialNumber != "" || subjectCN != ""):
		var prevCert *windows.CertContext
		for {
			handle, err = findCertificateInStore(st,
				encodingX509ASN|encodingPKCS7,
				0,
				findIssuerStr,
				uintptr(unsafe.Pointer(wide(issuerName))), prevCert)
			if err != nil {
				return nil, fmt.Errorf("findCertificateInStore failed: %w", err)
			}

			if handle == nil {
				return nil, apiv1.NotFoundError{Message: fmt.Sprintf("certificate with %s=%q not found", IssuerNameArg, issuerName)}
			}

			x509Cert, err := certContextToX509(handle)

			if err != nil {
				return nil, fmt.Errorf("could not unmarshal certificate to DER: %w", err)
			}

			switch {
			case len(serialNumber) > 0:
				// TODO: Replace this search with a CERT_ID + CERT_ISSUER_SERIAL_NUMBER search instead
				// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_id
				// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_issuer_serial_number
				var serialBytes []byte
				if strings.HasPrefix(serialNumber, "0x") {
					serialNumber = strings.TrimPrefix(serialNumber, "0x")
					serialNumber = strings.TrimPrefix(serialNumber, "00") // Comparison fails if leading 00 is not removed
					serialBytes, err = hex.DecodeString(serialNumber)
					if err != nil {
						return nil, fmt.Errorf("invalid hex format for %s: %w", SerialNumberArg, err)
					}
				} else {
					bi := new(big.Int)
					bi, ok := bi.SetString(serialNumber, 10)
					if !ok {
						return nil, fmt.Errorf("invalid %s - must be in hex or integer format", SerialNumberArg)
					}
					serialBytes = bi.Bytes()
				}

				if bytes.Equal(x509Cert.SerialNumber.Bytes(), serialBytes) {
					return handle, nil
				}
			case len(subjectCN) > 0:
				if x509Cert.Subject.CommonName == subjectCN {
					return handle, nil
				}
			}

			prevCert = handle
		}
	default:
		return nil, fmt.Errorf("%q, %q, or %q and %q is required to find a certificate", HashArg, KeyIDArg, IssuerNameArg, SerialNumberArg)
	}

	return handle, err
}

// CreateSigner returns a crypto.Signer that will sign using the key passed in via the URI.
func (k *CAPIKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	u, err := uri.ParseWithScheme(Scheme, req.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}

	var (
		kh            uintptr
		certHandle    *windows.CertContext
		containerName string
	)
	if containerName = u.Get(ContainerNameArg); containerName != "" {
		kh, err = nCryptOpenKey(k.providerHandle, containerName, 0, 0)
	} else {
		// check if a certificate can be located using the URI
		certHandle, err = k.getCertContext(&apiv1.LoadCertificateRequest{
			Name: req.SigningKey,
		})

		if err != nil {
			return nil, fmt.Errorf("%v not specified", ContainerNameArg)
		}

		kh, err = cryptFindCertificatePrivateKey(certHandle)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to open key: %w", err)
	}

	pinOrPass := u.Pin()
	if pinOrPass == "" {
		pinOrPass = k.pin
	}

	if pinOrPass != "" && k.providerName == ProviderMSSC {
		err = nCryptSetProperty(kh, NCRYPT_PIN_PROPERTY, pinOrPass, 0)

		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_PIN_PROPERTY: %w", err)
		}
	} else if pinOrPass != "" && k.providerName == ProviderMSPCP {
		passHash, err := hashPasswordUTF16(pinOrPass)
		if err != nil {
			return nil, fmt.Errorf("unable to hash password: %w", err)
		}

		err = nCryptSetProperty(kh, NCRYPT_PCP_USAGE_AUTH_PROPERTY, passHash, 0)

		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_PCP_USAGE_AUTH_PROPERTY: %w", err)
		}
	}

	return newCAPISigner(kh, containerName, pinOrPass)
}

func setKeySpec(u *uri.URI) (uint32, error) {
	keySpec := uint32(0) // default KeySpec value is NONE
	value := u.Get(KeySpec)
	if v := strings.ReplaceAll(strings.ToLower(value), "_", ""); v != "" {
		switch v {
		case "0", "none", "null":
			break // already set as the default
		case "1", "atkeyexchange":
			keySpec = uint32(1) // AT_KEYEXCHANGE
		case "2", "atsignature":
			keySpec = uint32(2) // AT_SIGNATURE
		default:
			return 0, fmt.Errorf("invalid value set for key-spec: %q", value)
		}
	}

	return keySpec, nil
}

// CreateKey generates a new key in the storage provider using nCryptCreatePersistedKey
func (k *CAPIKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
	}

	// The MSSC provider allows you to create keys without a certificate attached, but they seem to
	// be lost if the smartcard is removed, so refuse to create keys as a precaution
	if k.providerName == ProviderMSSC {
		return nil, fmt.Errorf("cannot create keys on %s", ProviderMSSC)
	}

	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}

	var containerName string
	if containerName = u.Get(ContainerNameArg); containerName == "" {
		// generate a uuid for the container name
		containerName, err = randutil.UUIDv4()
		if err != nil {
			return nil, fmt.Errorf("failed to generate uuid: %w", err)
		}
	}

	alg, ok := signatureAlgorithmMapping[req.SignatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm %v", req.SignatureAlgorithm)
	}

	keySpec, err := setKeySpec(u)
	if err != nil {
		return nil, fmt.Errorf("failed determining KeySpec to use: %w", err)
	}

	//TODO: check whether RSA keys require legacyKeySpec set to AT_KEYEXCHANGE
	kh, err := nCryptCreatePersistedKey(k.providerHandle, containerName, alg, keySpec, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to create persisted key: %w", err)
	}

	defer nCryptFreeObject(kh)

	if alg == "RSA" {
		err = nCryptSetProperty(kh, NCRYPT_LENGTH_PROPERTY, uint32(req.Bits), 0)

		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_LENGTH_PROPERTY: %w", err)
		}
	}

	// users can store the key as a machine key by passing in storelocation = machine
	// 'machine' is the only valid location, otherwise the key is stored as a 'user' key
	storeLocation := u.Get(StoreLocationArg)

	if storeLocation == "machine" {
		err = nCryptSetProperty(kh, NCRYPT_KEY_TYPE_PROPERTY, NCRYPT_MACHINE_KEY_FLAG, 0)

		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_KEY_TYPE_PROPERTY: %w", err)
		}
	} else if storeLocation != "" && storeLocation != "user" {
		return nil, fmt.Errorf("invalid storeLocation %v", storeLocation)
	}

	// if supplied, set the smart card pin/or PCP pass
	pinOrPass := u.Pin()

	//failover to pin set in kms instantiation
	if pinOrPass == "" {
		pinOrPass = k.pin
	}

	// TODO: investigate if there is a similar property for software backed keys
	if pinOrPass != "" && k.providerName == ProviderMSSC {
		err = nCryptSetProperty(kh, NCRYPT_PIN_PROPERTY, pinOrPass, 0)
		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_PIN_PROPERTY: %w", err)
		}
	} else if pinOrPass != "" && k.providerName == ProviderMSPCP {
		pwHash, err := hashPasswordUTF16(pinOrPass) // we have to SHA1 hash over the utf16 string

		if err != nil {
			return nil, fmt.Errorf("unable to hash pin: %w", err)
		}
		err = nCryptSetProperty(kh, NCRYPT_PCP_USAGE_AUTH_PROPERTY, pwHash, 0)
		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_PIN_PROPERTY: %w", err)
		}
	}

	err = nCryptFinalizeKey(kh, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to finalize key: %w", err)
	}

	uc, err := nCryptGetPropertyStr(kh, NCRYPT_UNIQUE_NAME_PROPERTY)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve NCRYPT_UNIQUE_NAME_PROPERTY: %w", err)
	}

	pub, err := getPublicKey(kh)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve public key: %w", err)
	}

	createdKeyURI := fmt.Sprintf("%s:%s=%s;%s=%s", Scheme, ProviderNameArg, k.providerName, ContainerNameArg, uc)

	return &apiv1.CreateKeyResponse{
		Name:      createdKeyURI,
		PublicKey: pub,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: createdKeyURI,
		},
	}, nil
}

// GetPublicKey returns the public key from the key id (Microsoft calls it 'Key Container Name') passed in via the URI
func (k *CAPIKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}

	var containerName string
	if containerName = u.Get(ContainerNameArg); containerName == "" {
		return nil, fmt.Errorf("%v not specified", ContainerNameArg)
	}

	kh, err := nCryptOpenKey(k.providerHandle, containerName, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to open key: %w", err)
	}

	defer nCryptFreeObject(kh)

	return getPublicKey(kh)
}

// LoadCertificate will return an x509.Certificate if passed a URI containing a subject key
// identifier (key-id) or sha1 hash
func (k *CAPIKMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	certHandle, err := k.getCertContext(req)
	if err != nil {
		return nil, err
	}

	defer windows.CertFreeCertificateContext(certHandle)
	return certContextToX509(certHandle)
}

func (k *CAPIKMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return fmt.Errorf("failed to parse URI: %w", err)
	}

	var storeLocation string
	if storeLocation = u.Get(StoreLocationArg); storeLocation == "" {
		storeLocation = "user"
	}

	var certStoreLocation uint32
	switch storeLocation {
	case "user":
		certStoreLocation = certStoreCurrentUser
	case "machine":
		certStoreLocation = certStoreLocalMachine
	default:
		return fmt.Errorf("invalid cert store location %q", storeLocation)
	}

	var storeName string
	if storeName = u.Get(StoreNameArg); storeName == "" {
		storeName = "My"
	}

	certContext, err := windows.CertCreateCertificateContext(
		encodingX509ASN|encodingPKCS7,
		&req.Certificate.Raw[0],
		uint32(len(req.Certificate.Raw)))
	if err != nil {
		return fmt.Errorf("CertCreateCertificateContext returned: %w", err)
	}
	defer windows.CertFreeCertificateContext(certContext)

	// looking up the certificate private key is performed by default, but is made optional,
	// so that looking up the private key for e.g. intermediate certificates can be skipped.
	// If not skipped, looking up a private key can prompt the user to insert/select a smart
	// card, which is usually not what we want to happen.
	if !u.GetBool(SkipFindCertificateKey) {
		// TODO: not finding the associated private key is not a dealbreaker, but maybe a warning should be issued
		cryptFindCertificateKeyProvInfo(certContext)
	}

	st, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocation,
		uintptr(unsafe.Pointer(wide(storeName))))
	if err != nil {
		return fmt.Errorf("CertOpenStore for the %q store %q returned: %w", storeLocation, storeName, err)
	}

	// Add the cert context to the system certificate store
	if err = windows.CertAddCertificateContextToStore(st, certContext, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore returned: %w", err)
	}

	return nil
}

// DeleteCertificate deletes a certificate from the Windows certificate store. It uses
// largely the same logic for searching for the certificate as [LoadCertificate], but
// deletes it as soon as it's found.
//
// # Experimental
//
// Notice: This method is EXPERIMENTAL and may be changed or removed in a later
// release.
func (k *CAPIKMS) DeleteCertificate(req *apiv1.DeleteCertificateRequest) error {
	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return fmt.Errorf("failed to parse URI: %w", err)
	}

	sha1Hash, err := u.GetHexEncoded(HashArg)
	if err != nil {
		return fmt.Errorf("failed getting %s from URI %q: %w", HashArg, req.Name, err)
	}
	keyID := u.Get(KeyIDArg)
	issuerName := u.Get(IssuerNameArg)
	serialNumber := u.Get(SerialNumberArg)

	var storeLocation string
	if storeLocation = u.Get(StoreLocationArg); storeLocation == "" {
		storeLocation = "user"
	}

	var certStoreLocation uint32
	switch storeLocation {
	case "user":
		certStoreLocation = certStoreCurrentUser
	case "machine":
		certStoreLocation = certStoreLocalMachine
	default:
		return fmt.Errorf("invalid cert store location %q", storeLocation)
	}

	var storeName string
	if storeName = u.Get(StoreNameArg); storeName == "" {
		storeName = "My"
	}

	st, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocation,
		uintptr(unsafe.Pointer(wide(storeName))))
	if err != nil {
		return fmt.Errorf("CertOpenStore for the %q store %q returned: %w", storeLocation, storeName, err)
	}

	var certHandle *windows.CertContext

	switch {
	case len(sha1Hash) > 0:
		if len(sha1Hash) != 20 {
			return fmt.Errorf("decoded %s has length %d; expected 20 bytes for SHA-1", HashArg, len(sha1Hash))
		}
		searchData := CERT_ID_KEYIDORHASH{
			idChoice: CERT_ID_SHA1_HASH,
			KeyIDOrHash: CRYPTOAPI_BLOB{
				len:  uint32(len(sha1Hash)),
				data: uintptr(unsafe.Pointer(&sha1Hash[0])),
			},
		}
		certHandle, err = findCertificateInStore(st,
			encodingX509ASN|encodingPKCS7,
			0,
			findCertID,
			uintptr(unsafe.Pointer(&searchData)), nil)
		if err != nil {
			return fmt.Errorf("findCertificateInStore failed: %w", err)
		}
		if certHandle == nil {
			return nil
		}

		if err := windows.CertDeleteCertificateFromStore(certHandle); err != nil {
			return fmt.Errorf("failed removing certificate: %w", err)
		}
		return nil
	case keyID != "":
		keyID = strings.TrimPrefix(keyID, "0x") // Support specifying the hash as 0x like with serial

		keyIDBytes, err := hex.DecodeString(keyID)
		if err != nil {
			return fmt.Errorf("%s must be in hex format: %w", KeyIDArg, err)
		}
		searchData := CERT_ID_KEYIDORHASH{
			idChoice: CERT_ID_KEY_IDENTIFIER,
			KeyIDOrHash: CRYPTOAPI_BLOB{
				len:  uint32(len(keyIDBytes)),
				data: uintptr(unsafe.Pointer(&keyIDBytes[0])),
			},
		}
		certHandle, err = findCertificateInStore(st,
			encodingX509ASN|encodingPKCS7,
			0,
			findCertID,
			uintptr(unsafe.Pointer(&searchData)), nil)
		if err != nil {
			return fmt.Errorf("findCertificateInStore failed: %w", err)
		}
		if certHandle == nil {
			return nil
		}

		if err := windows.CertDeleteCertificateFromStore(certHandle); err != nil {
			return fmt.Errorf("failed removing certificate: %w", err)
		}
		return nil
	case issuerName != "" && serialNumber != "":
		//TODO: Replace this search with a CERT_ID + CERT_ISSUER_SERIAL_NUMBER search instead
		// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_id
		// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_issuer_serial_number
		var serialBytes []byte
		if strings.HasPrefix(serialNumber, "0x") {
			serialNumber = strings.TrimPrefix(serialNumber, "0x")
			serialNumber = strings.TrimPrefix(serialNumber, "00") // Comparison fails if leading 00 is not removed
			serialBytes, err = hex.DecodeString(serialNumber)
			if err != nil {
				return fmt.Errorf("invalid hex format for %s: %w", SerialNumberArg, err)
			}
		} else {
			bi := new(big.Int)
			bi, ok := bi.SetString(serialNumber, 10)
			if !ok {
				return fmt.Errorf("invalid %s - must be in hex or integer format", SerialNumberArg)
			}
			serialBytes = bi.Bytes()
		}
		var prevCert *windows.CertContext
		for {
			certHandle, err = findCertificateInStore(st,
				encodingX509ASN|encodingPKCS7,
				0,
				findIssuerStr,
				uintptr(unsafe.Pointer(wide(issuerName))), prevCert)

			if err != nil {
				return fmt.Errorf("findCertificateInStore failed: %w", err)
			}
			if certHandle == nil {
				return nil
			}

			x509Cert, err := certContextToX509(certHandle)
			if err != nil {
				defer windows.CertFreeCertificateContext(certHandle)
				return fmt.Errorf("could not unmarshal certificate to DER: %w", err)
			}

			if bytes.Equal(x509Cert.SerialNumber.Bytes(), serialBytes) {
				if err := windows.CertDeleteCertificateFromStore(certHandle); err != nil {
					return fmt.Errorf("failed removing certificate: %w", err)
				}

				return nil
			}
			prevCert = certHandle
		}
	default:
		return fmt.Errorf("%q, %q, or %q and %q is required to find a certificate", HashArg, KeyIDArg, IssuerNameArg, SerialNumberArg)
	}
}

type CAPISigner struct {
	algorithmGroup string
	keyHandle      uintptr
	containerName  string
	PublicKey      crypto.PublicKey
}

func newCAPISigner(kh uintptr, containerName, pin string) (crypto.Signer, error) {
	pub, err := getPublicKey(kh)
	if err != nil {
		return nil, fmt.Errorf("unable to get public key: %w", err)
	}

	algGroup, err := nCryptGetPropertyStr(kh, NCRYPT_ALGORITHM_GROUP_PROPERTY)
	if err != nil {
		return nil, fmt.Errorf("unable to get NCRYPT_ALGORITHM_GROUP_PROPERTY: %w", err)
	}

	signer := CAPISigner{
		algorithmGroup: algGroup,
		keyHandle:      kh,
		containerName:  containerName,
		PublicKey:      pub,
	}

	return &signer, nil
}

func (s *CAPISigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch s.algorithmGroup {
	case "ECDSA":
		signatureBytes, err := nCryptSignHash(s.keyHandle, digest, "", 0)

		if err != nil {
			return nil, err
		}

		if len(signatureBytes) >= len(digest)*2 {
			sigR := signatureBytes[:len(digest)]
			sigS := signatureBytes[len(digest):]

			var b cryptobyte.Builder
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1BigInt(new(big.Int).SetBytes(sigR))
				b.AddASN1BigInt(new(big.Int).SetBytes(sigS))
			})
			return b.Bytes()
		}

		return nil, fmt.Errorf("signatureBytes not long enough to encode ASN signature")
	case "RSA":
		hf := opts.HashFunc()
		hashAlg, ok := hashAlgorithms[hf]
		if !ok {
			return nil, fmt.Errorf("unsupported RSA hash algorithm %v", hf)
		}

		var saltLength int
		if rsaOpts, ok := opts.(*rsa.PSSOptions); ok {
			if rsaOpts.SaltLength == rsa.PSSSaltLengthEqualsHash {
				rsaOpts.SaltLength = rsaOpts.Hash.Size()
			}

			saltLength = rsaOpts.SaltLength
		}

		signatureBytes, err := nCryptSignHash(s.keyHandle, digest, hashAlg, saltLength)

		if err != nil {
			return nil, fmt.Errorf("NCryptSignHash failed: %w", err)
		}

		return signatureBytes, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm group %v", s.algorithmGroup)
	}
}

func (s *CAPISigner) Public() crypto.PublicKey {
	return s.PublicKey
}

var _ apiv1.CertificateManager = (*CAPIKMS)(nil)
