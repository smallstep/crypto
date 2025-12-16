//go:build windows && !nocapi

package capi

import (
	"bytes"
	"cmp"
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
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/pkg/errors"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/sys/windows"

	"go.step.sm/crypto/fingerprint"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/randutil"
)

// Scheme is the scheme used in uris, the string "capi".
const Scheme = string(apiv1.CAPIKMS)

const (
	ProviderNameArg              = "provider"
	ContainerNameArg             = "key"
	HashArg                      = "sha1"
	StoreLocationArg             = "store-location" // 'machine', 'user', etc
	StoreNameArg                 = "store"          // 'MY', 'CA', 'ROOT', etc
	IntermediateStoreLocationArg = "intermediate-store-location"
	IntermediateStoreNameArg     = "intermediate-store"
	KeyIDArg                     = "key-id"
	SubjectCNArg                 = "cn"
	SerialNumberArg              = "serial"
	IssuerNameArg                = "issuer"
	KeySpec                      = "key-spec"                  // 0, 1, 2; none/NONE, at_keyexchange/AT_KEYEXCHANGE, at_signature/AT_SIGNATURE
	SkipFindCertificateKey       = "skip-find-certificate-key" // skips looking up certificate private key when storing a certificate
)

const (
	MachineStoreLocation = "machine"
	UserStoreLocation    = "user"
	MyStore              = "My"
	CAStore              = "CA" // TODO(hs): verify "CA" works for "machine" certs too

	// Deprecated: use MachineStoreLocation
	MachineStore = MachineStoreLocation
	// Deprecated: use UserStoreLocation
	UserStore = UserStoreLocation
)

// maximumIterations is the maximum number of times for the recursive
// intermediate CA lookup loop.
const maximumIterations = 10

var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]string{
	apiv1.UnspecifiedSignAlgorithm: ALG_ECDSA_P256,
	apiv1.SHA256WithRSA:            ALG_RSA,
	apiv1.SHA384WithRSA:            ALG_RSA,
	apiv1.SHA512WithRSA:            ALG_RSA,
	apiv1.ECDSAWithSHA256:          ALG_ECDSA_P256,
	apiv1.ECDSAWithSHA384:          ALG_ECDSA_P384,
	apiv1.ECDSAWithSHA512:          ALG_ECDSA_P521,
}

type uriAttributes struct {
	containerName             string
	hash                      []byte
	storeLocation             string
	storeName                 string
	intermediateStoreLocation string
	intermediateStoreName     string
	keyID                     []byte
	subjectCN                 string
	serialNumber              string
	issuerName                string
	keySpec                   string
	skipFindCertificateKey    bool
	pin                       string
}

func parseURI(rawuri string) (*uriAttributes, error) {
	u, err := uri.ParseWithScheme(Scheme, rawuri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}

	var hashValue []byte
	if u.Has(HashArg) {
		if hashValue, err = u.GetHexEncoded(HashArg); err != nil {
			return nil, fmt.Errorf("failed getting %s from URI %q: %w", HashArg, rawuri, err)
		}
	}

	var keyIDValue []byte
	if u.Has(KeyIDArg) {
		if keyIDValue, err = u.GetHexEncoded(KeyIDArg); err != nil {
			return nil, fmt.Errorf("failed getting %s from URI %q: %w", KeyIDArg, rawuri, err)
		}
	}

	return &uriAttributes{
		containerName:             u.Get(ContainerNameArg),
		hash:                      hashValue,
		storeLocation:             cmp.Or(u.Get(StoreLocationArg), UserStoreLocation),
		storeName:                 cmp.Or(u.Get(StoreNameArg), MyStore),
		intermediateStoreLocation: cmp.Or(u.Get(IntermediateStoreLocationArg), UserStoreLocation),
		intermediateStoreName:     cmp.Or(u.Get(IntermediateStoreNameArg), CAStore),
		keyID:                     keyIDValue,
		subjectCN:                 u.Get(SubjectCNArg),
		serialNumber:              u.Get(SerialNumberArg),
		issuerName:                u.Get(IssuerNameArg),
		keySpec:                   u.Get(KeySpec),
		skipFindCertificateKey:    u.GetBool(SkipFindCertificateKey),
		pin:                       u.Pin(),
	}, nil
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
	providerName := ProviderMSKSP
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
func (k *CAPIKMS) getCertContext(u *uriAttributes) (*windows.CertContext, error) {
	// The hash argument is a SHA-1
	if len(u.hash) > 0 && len(u.hash) != 20 {
		return nil, fmt.Errorf("decoded %s has length %d; expected 20 bytes for SHA-1", HashArg, len(u.hash))
	}

	var certStoreLocation uint32
	switch u.storeLocation {
	case UserStoreLocation:
		certStoreLocation = certStoreCurrentUser
	case MachineStoreLocation:
		certStoreLocation = certStoreLocalMachine
	default:
		return nil, fmt.Errorf("invalid cert store location %q", u.storeLocation)
	}

	st, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocation,
		uintptr(unsafe.Pointer(wide(u.storeName))))
	if err != nil {
		return nil, fmt.Errorf("CertOpenStore for the %q store %q returned: %w", u.storeLocation, u.storeName, err)
	}

	var handle *windows.CertContext

	switch {
	case len(u.hash) > 0:
		searchData := CERT_ID_KEYIDORHASH{
			idChoice: CERT_ID_SHA1_HASH,
			KeyIDOrHash: CRYPTOAPI_BLOB{
				len:  uint32(len(u.hash)),
				data: uintptr(unsafe.Pointer(&u.hash[0])),
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
			return nil, apiv1.NotFoundError{Message: fmt.Sprintf("certificate with %s=%x not found", HashArg, u.hash)}
		}
	case len(u.keyID) > 0:
		searchData := CERT_ID_KEYIDORHASH{
			idChoice: CERT_ID_KEY_IDENTIFIER,
			KeyIDOrHash: CRYPTOAPI_BLOB{
				len:  uint32(len(u.keyID)),
				data: uintptr(unsafe.Pointer(&u.keyID[0])),
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
			return nil, apiv1.NotFoundError{Message: fmt.Sprintf("certificate with %s=%x not found", KeyIDArg, u.keyID)}
		}
	case u.issuerName != "" && (u.serialNumber != "" || u.subjectCN != ""):
		var prevCert *windows.CertContext
		for {
			handle, err = findCertificateInStore(st,
				encodingX509ASN|encodingPKCS7,
				0,
				findIssuerStr,
				uintptr(unsafe.Pointer(wide(u.issuerName))), prevCert)
			if err != nil {
				return nil, fmt.Errorf("findCertificateInStore failed: %w", err)
			}

			if handle == nil {
				return nil, apiv1.NotFoundError{Message: fmt.Sprintf("certificate with %s=%q not found", IssuerNameArg, u.issuerName)}
			}

			x509Cert, err := certContextToX509(handle)
			if err != nil {
				return nil, fmt.Errorf("could not unmarshal certificate to DER: %w", err)
			}

			switch {
			case len(u.serialNumber) > 0:
				// TODO: Replace this search with a CERT_ID + CERT_ISSUER_SERIAL_NUMBER search instead
				// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_id
				// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_issuer_serial_number
				var bi *big.Int
				if strings.HasPrefix(u.serialNumber, "0x") {
					serialBytes, err := hex.DecodeString(strings.TrimPrefix(u.serialNumber, "0x"))
					if err != nil {
						return nil, fmt.Errorf("invalid hex format for %s: %w", SerialNumberArg, err)
					}

					bi = new(big.Int).SetBytes(serialBytes)
				} else {
					bi := new(big.Int)
					bi, ok := bi.SetString(u.serialNumber, 10)
					if !ok {
						return nil, fmt.Errorf("invalid %s - must be in hex or integer format", SerialNumberArg)
					}
				}

				if x509Cert.SerialNumber.Cmp(bi) == 0 {
					return handle, nil
				}
			case len(u.subjectCN) > 0:
				if x509Cert.Subject.CommonName == u.subjectCN {
					return handle, nil
				}
			}

			prevCert = handle
		}
	default:
		return nil, fmt.Errorf("%q, %q, or %q and one of %q or %q is required to find a certificate", HashArg, KeyIDArg, IssuerNameArg, SerialNumberArg, SubjectCNArg)
	}

	return handle, err
}

// CreateSigner returns a crypto.Signer that will sign using the key passed in via the URI.
func (k *CAPIKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	u, err := parseURI(req.SigningKey)
	if err != nil {
		return nil, err
	}

	var (
		kh         uintptr
		certHandle *windows.CertContext
	)

	if u.containerName != "" {
		keyFlags, err := k.getKeyFlags(u)
		if err != nil {
			return nil, err
		}

		kh, err = nCryptOpenKey(k.providerHandle, u.containerName, 0, keyFlags)
		if err != nil {
			return nil, fmt.Errorf("unable to open key using %q=%q: %w", ContainerNameArg, u.containerName, err)
		}
	} else {
		// check if a certificate can be located using the URI
		certHandle, err = k.getCertContext(u)
		if err != nil {
			return nil, fmt.Errorf("%v not specified", ContainerNameArg)
		}

		kh, err = cryptFindCertificatePrivateKey(certHandle)
		if err != nil {
			return nil, fmt.Errorf("unable to open key: %w", err)
		}
	}

	if u.pin == "" {
		u.pin = k.pin
	}

	if u.pin != "" && k.providerName == ProviderMSSC {
		err = nCryptSetProperty(kh, NCRYPT_PIN_PROPERTY, u.pin, 0)
		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_PIN_PROPERTY: %w", err)
		}
	} else if u.pin != "" && k.providerName == ProviderMSPCP {
		passHash, err := hashPasswordUTF16(u.pin)
		if err != nil {
			return nil, fmt.Errorf("unable to hash password: %w", err)
		}

		err = nCryptSetProperty(kh, NCRYPT_PCP_USAGE_AUTH_PROPERTY, passHash, 0)
		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_PCP_USAGE_AUTH_PROPERTY: %w", err)
		}
	}

	return newCAPISigner(kh, u.containerName, u.pin)
}

func setKeySpec(u *uriAttributes) (uint32, error) {
	keySpec := uint32(0) // default KeySpec value is NONE
	if v := strings.ReplaceAll(strings.ToLower(u.keySpec), "_", ""); v != "" {
		switch v {
		case "0", "none", "null":
			break // already set as the default
		case "1", "atkeyexchange":
			keySpec = uint32(1) // AT_KEYEXCHANGE
		case "2", "atsignature":
			keySpec = uint32(2) // AT_SIGNATURE
		default:
			return 0, fmt.Errorf("invalid value set for key-spec: %q", u.keySpec)
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

	u, err := parseURI(req.Name)
	if err != nil {
		return nil, err
	}

	// generate a random uuid for the container name if it is not present
	if u.containerName == "" {
		u.containerName, err = randutil.UUIDv4()
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

	keyFlags, err := k.getKeyFlags(u)
	if err != nil {
		return nil, err
	}

	// TODO: check whether RSA keys require legacyKeySpec set to AT_KEYEXCHANGE
	kh, err := nCryptCreatePersistedKey(k.providerHandle, u.containerName, alg, keySpec, keyFlags)
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

	// if supplied, set the smart card pin/or PCP pass, failover to pin set in
	// kms instantiation
	if u.pin == "" {
		u.pin = k.pin
	}

	// TODO: investigate if there is a similar property for software backed keys
	if u.pin != "" && k.providerName == ProviderMSSC {
		err = nCryptSetProperty(kh, NCRYPT_PIN_PROPERTY, u.pin, 0)
		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_PIN_PROPERTY: %w", err)
		}
	} else if u.pin != "" && k.providerName == ProviderMSPCP {
		pwHash, err := hashPasswordUTF16(u.pin) // we have to SHA1 hash over the utf16 string
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

// DeleteKey deletes the key from the key id (Microsoft calls it 'Key Container Name') passed in via the URI
func (k *CAPIKMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	u, err := parseURI(req.Name)
	if err != nil {
		return err
	}

	if u.containerName == "" {
		return fmt.Errorf("%v not specified", ContainerNameArg)
	}

	keyFlags, err := k.getKeyFlags(u)
	if err != nil {
		return err
	}

	kh, err := nCryptOpenKey(k.providerHandle, u.containerName, 0, keyFlags)
	if err != nil {
		return fmt.Errorf("unable to open key: %w", err)
	}

	defer nCryptFreeObject(kh)

	return nCryptDeleteKey(kh)
}

// GetPublicKey returns the public key from the key id (Microsoft calls it 'Key Container Name') passed in via the URI
func (k *CAPIKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	u, err := parseURI(req.Name)
	if err != nil {
		return nil, err
	}

	if u.containerName == "" {
		return nil, fmt.Errorf("%v not specified", ContainerNameArg)
	}

	keyFlags, err := k.getKeyFlags(u)
	if err != nil {
		return nil, err
	}

	kh, err := nCryptOpenKey(k.providerHandle, u.containerName, 0, keyFlags)
	if err != nil {
		return nil, fmt.Errorf("unable to open key: %w", err)
	}

	defer nCryptFreeObject(kh)

	return getPublicKey(kh)
}

// LoadCertificate will return an x509.Certificate if passed a URI containing a subject key
// identifier (key-id) or sha1 hash
func (k *CAPIKMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	u, err := parseURI(req.Name)
	if err != nil {
		return nil, err
	}

	certHandle, err := k.getCertContext(u)
	if err != nil {
		return nil, err
	}

	defer windows.CertFreeCertificateContext(certHandle)
	return certContextToX509(certHandle)
}

func (k *CAPIKMS) LoadCertificateChain(req *apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	u, err := parseURI(req.Name)
	if err != nil {
		return nil, err
	}

	cert, err := k.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: req.Name,
	})
	if err != nil {
		return nil, err
	}

	chain := []*x509.Certificate{cert}
	child := cert
	for i := 0; i < maximumIterations; i++ { // loop a maximum number of times
		authorityKeyID := hex.EncodeToString(child.AuthorityKeyId)
		parent, err := k.LoadCertificate(&apiv1.LoadCertificateRequest{
			Name: uri.New(Scheme, url.Values{
				KeyIDArg:         []string{authorityKeyID},
				StoreLocationArg: []string{u.intermediateStoreLocation},
				StoreNameArg:     []string{u.intermediateStoreName},
			}).String(),
		})
		if err != nil {
			if errors.Is(err, apiv1.NotFoundError{}) {
				// if error indicates the parent wasn't found, assume end of chain for a specific
				// combination of store location and store is reached, and break from the loop
				break
			}
			return nil, fmt.Errorf("failed loading intermediate CA certificate using Windows platform cryptography provider: %w", err)
		}

		// if the discovered parent has a signature from itself, assume it's a root CA,
		// and break from the loop
		if parent.CheckSignatureFrom(parent) == nil {
			break
		}

		// ensure child has a valid signature from the parent
		if err := child.CheckSignatureFrom(parent); err != nil {
			return nil, fmt.Errorf("failed loading intermediate CA certificate using Windows platform cryptography provider: %w", err)
		}

		chain = append(chain, parent)
		child = parent
	}

	return chain, nil
}

func (k *CAPIKMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	u, err := parseURI(req.Name)
	if err != nil {
		return err
	}

	var certStoreLocation uint32
	switch u.storeLocation {
	case UserStoreLocation:
		certStoreLocation = certStoreCurrentUser
	case MachineStoreLocation:
		certStoreLocation = certStoreLocalMachine
	default:
		return fmt.Errorf("invalid cert store location %q", u.storeLocation)
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
	if !u.skipFindCertificateKey {
		// TODO: not finding the associated private key is not a dealbreaker, but maybe a warning should be issued
		cryptFindCertificateKeyProvInfo(certContext)
	}

	st, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocation,
		uintptr(unsafe.Pointer(wide(u.storeName))))
	if err != nil {
		return fmt.Errorf("CertOpenStore for the %q store %q returned: %w", u.storeLocation, u.storeName, err)
	}

	// Add the cert context to the system certificate store
	if err = windows.CertAddCertificateContextToStore(st, certContext, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore returned: %w", err)
	}

	return nil
}

func (k *CAPIKMS) StoreCertificateChain(req *apiv1.StoreCertificateChainRequest) error {
	u, err := parseURI(req.Name)
	if err != nil {
		return err
	}

	leaf := req.CertificateChain[0]
	fp, err := fingerprint.New(leaf.Raw, crypto.SHA1, fingerprint.HexFingerprint)
	if err != nil {
		return fmt.Errorf("failed calculating certificate SHA1 fingerprint: %w", err)
	}

	if err := k.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: uri.New("capi", url.Values{
			HashArg:                []string{fp},
			StoreLocationArg:       []string{u.storeLocation},
			StoreNameArg:           []string{u.storeName},
			SkipFindCertificateKey: []string{strconv.FormatBool(u.skipFindCertificateKey)},
		}).String(),
		Certificate: leaf,
	}); err != nil {
		return fmt.Errorf("failed storing certificate using Windows platform cryptography provider: %w", err)
	}

	if len(req.CertificateChain) == 1 {
		return nil
	}

	for _, c := range req.CertificateChain[1:] {
		if err := validateIntermediateCertificate(c); err != nil {
			return fmt.Errorf("invalid intermediate certificate provided in chain: %w", err)
		}

		fp, err := fingerprint.New(c.Raw, crypto.SHA1, fingerprint.HexFingerprint)
		if err != nil {
			return fmt.Errorf("failed calculating certificate SHA1 fingerprint: %w", err)
		}

		if err := k.StoreCertificate(&apiv1.StoreCertificateRequest{
			Name: uri.New("capi", url.Values{
				HashArg:                []string{fp},
				StoreLocationArg:       []string{u.intermediateStoreLocation},
				StoreNameArg:           []string{u.intermediateStoreName},
				SkipFindCertificateKey: []string{"true"},
			}).String(),
			Certificate: c,
		}); err != nil {
			return err
		}
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
	u, err := parseURI(req.Name)
	if err != nil {
		return err
	}

	var certStoreLocation uint32
	switch u.storeLocation {
	case UserStoreLocation:
		certStoreLocation = certStoreCurrentUser
	case MachineStoreLocation:
		certStoreLocation = certStoreLocalMachine
	default:
		return fmt.Errorf("invalid cert store location %q", u.storeLocation)
	}

	st, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocation,
		uintptr(unsafe.Pointer(wide(u.storeName))))
	if err != nil {
		return fmt.Errorf("CertOpenStore for the %q store %q returned: %w", u.storeLocation, u.storeName, err)
	}

	var certHandle *windows.CertContext

	switch {
	case len(u.hash) > 0:
		if len(u.hash) != 20 {
			return fmt.Errorf("decoded %s has length %d; expected 20 bytes for SHA-1", HashArg, len(u.hash))
		}
		searchData := CERT_ID_KEYIDORHASH{
			idChoice: CERT_ID_SHA1_HASH,
			KeyIDOrHash: CRYPTOAPI_BLOB{
				len:  uint32(len(u.hash)),
				data: uintptr(unsafe.Pointer(&u.hash[0])),
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
	case len(u.keyID) > 0:
		searchData := CERT_ID_KEYIDORHASH{
			idChoice: CERT_ID_KEY_IDENTIFIER,
			KeyIDOrHash: CRYPTOAPI_BLOB{
				len:  uint32(len(u.keyID)),
				data: uintptr(unsafe.Pointer(&u.keyID[0])),
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
	case u.issuerName != "" && u.serialNumber != "":
		// TODO: Replace this search with a CERT_ID + CERT_ISSUER_SERIAL_NUMBER search instead
		// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_id
		// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_issuer_serial_number
		var serialBytes []byte
		if strings.HasPrefix(u.serialNumber, "0x") {
			u.serialNumber = strings.TrimPrefix(u.serialNumber, "0x")
			u.serialNumber = strings.TrimPrefix(u.serialNumber, "00") // Comparison fails if leading 00 is not removed
			serialBytes, err = hex.DecodeString(u.serialNumber)
			if err != nil {
				return fmt.Errorf("invalid hex format for %s: %w", SerialNumberArg, err)
			}
		} else {
			bi := new(big.Int)
			bi, ok := bi.SetString(u.serialNumber, 10)
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
				uintptr(unsafe.Pointer(wide(u.issuerName))), prevCert)
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

func (k *CAPIKMS) getKeyFlags(u *uriAttributes) (uint32, error) {
	keyFlags := uint32(0)

	switch u.storeLocation {
	case MachineStoreLocation:
		if k.providerName == ProviderMSSC {
			return 0, fmt.Errorf("machine store cannot be used with the %s", ProviderMSSC)
		}

		keyFlags |= NCRYPT_MACHINE_KEY_FLAG

	case UserStoreLocation:
		if k.providerName == ProviderMSPCP {
			return 0, fmt.Errorf("user store cannot be used with the %s", ProviderMSPCP)
		}

	case "":

	default:
		return 0, fmt.Errorf("invalid storeLocation %v", u.storeLocation)
	}

	return keyFlags, nil
}

type CAPISigner struct {
	algorithmGroup string
	keyHandle      uintptr
	containerName  string
	PublicKey      crypto.PublicKey
}

func newCAPISigner(kh uintptr, containerName, _ string) (crypto.Signer, error) {
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

		half := len(signatureBytes) >> 1
		sigR := signatureBytes[:half]
		sigS := signatureBytes[half:]

		var b cryptobyte.Builder
		b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1BigInt(new(big.Int).SetBytes(sigR))
			b.AddASN1BigInt(new(big.Int).SetBytes(sigS))
		})
		return b.Bytes()

	case "RSA":
		hf := opts.HashFunc()
		hashAlg, ok := hashAlgorithms[hf]
		if !ok {
			return nil, fmt.Errorf("unsupported RSA hash algorithm %v", hf)
		}

		var saltLength int
		if rsaOpts, ok := opts.(*rsa.PSSOptions); ok {
			switch rsaOpts.SaltLength {
			case rsa.PSSSaltLengthAuto:
				if k, ok := s.PublicKey.(*rsa.PublicKey); ok {
					saltLength = (k.N.BitLen()-1+7)/8 - 2 - rsaOpts.Hash.Size()
				} else {
					return nil, fmt.Errorf("unexpected RSA key type %T", s.PublicKey)
				}
			case rsa.PSSSaltLengthEqualsHash:
				saltLength = rsaOpts.Hash.Size()
			default:
				saltLength = rsaOpts.SaltLength
			}
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

func validateIntermediateCertificate(c *x509.Certificate) error {
	switch {
	case !c.IsCA:
		return fmt.Errorf("certificate with serial %q is not a CA certificate", c.SerialNumber.String())
	case !c.BasicConstraintsValid:
		return fmt.Errorf("certificate with serial %q has invalid basic constraints", c.SerialNumber.String())
	case bytes.Equal(c.AuthorityKeyId, c.SubjectKeyId):
		return fmt.Errorf("certificate with serial %q has equal subject and authority key IDs", c.SerialNumber.String())
	case c.CheckSignatureFrom(c) == nil:
		return fmt.Errorf("certificate with serial %q is self-signed root CA", c.SerialNumber.String())
	}

	return nil
}

var _ apiv1.CertificateManager = (*CAPIKMS)(nil)
