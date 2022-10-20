//go:build windows
// +build windows

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
	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/randutil"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/sys/windows"
	"io"
	"math/big"
	"reflect"
	"unsafe"
)

// Scheme is the scheme used in uris.
const Scheme = "capi"

const (
	ProviderNameArg  = "provider"
	ContainerNameArg = "key"
	HashArg          = "sha1"
	StoreLocationArg = "store-location" // 'machine', 'user', etc
	StoreNameArg     = "store"          // 'MY', 'CA', 'ROOT', etc
)

var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]string{
	apiv1.UnspecifiedSignAlgorithm: "ECDSA_P256",
	apiv1.SHA256WithRSA:            "RSA",
	apiv1.SHA512WithRSA:            "RSA",
	apiv1.SHA256WithRSAPSS:         "RSA",
	apiv1.SHA512WithRSAPSS:         "RSA",
	apiv1.ECDSAWithSHA256:          "ECDSA_P256",
	apiv1.ECDSAWithSHA384:          "ECDSA_P384",
	apiv1.ECDSAWithSHA512:          "ECDSA_P521",
}

// CAPIKMS implements a KMS using Windows CryptoAPI (CAPI) and Next-Gen CryptoAPI (CNG).
//
// The URI format used in CAPIKMS is the following:
//
//   - capi:provider=STORAGE-PROVIDER;key=KEY-NAME
//
// For certificates:
//   - capi:store-location=[machine|user];store=My;sha1=THUMBPRINT
//
// The scheme is "capi";
//
// "provider" is the provider name and can be one of:
// - "Microsoft Software Key Storage Provider"
// - "Microsoft Smart Card Key Storage Provider"
// - "Microsoft Platform Crypto Provider"
// if not set it defaults to "Microsoft Software Key Storage Provider"
//
// "key" is the key container name. If not set one is generated.
//
// "store-location" specifies the certificate store location - "user" or "machine"
//
// "store" is the certificate store name - "My", "Root", and "CA" are some examples
//
// "sha1" is the sha1 thumbprint of the certificate to load
//
type CAPIKMS struct {
	providerName   string
	providerHandle uintptr
	containerName  string
	pin            string
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
			return nil, fmt.Errorf("elliptic curve bloc did not contain expected magic")
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
		return nil, errors.Wrap(err, "GetPublicKey unable to get NCRYPT_ALGORITHM_GROUP_PROPERTY")
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
			return nil, fmt.Errorf("failed to retrieve ECC curve name: %w", err)
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
	var providerName string
	containerName, err := randutil.UUIDv4()
	providerName = "Microsoft Software Key Storage Provider"
	pin := ""

	if err != nil {
		return nil, fmt.Errorf("could not generate UUIDv4: %w", err)
	}

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
	ph, err := nCryptOpenStorage(providerName)

	if err != nil {
		return nil, fmt.Errorf("could not open nCrypt provider: %w", err)
	}

	return &CAPIKMS{
		providerName:   providerName,
		providerHandle: ph,
		containerName:  containerName,
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

// CreateSigner returns a new signer configured with the given signing key.
func (k *CAPIKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	var u *uri.URI

	u, err := uri.ParseWithScheme(Scheme, req.SigningKey)
	if err != nil {
		return nil, errors.Wrap(err, "CreateSigner failed to parse URI")
	}

	if k.containerName = u.Get(ContainerNameArg); k.containerName == "" {
		return nil, errors.Errorf("CreateSigner %v not specified", ContainerNameArg)
	}

	scPIN := u.Pin()

	if scPIN == "" {
		scPIN = k.pin
	}

	return newCAPISigner(k.providerHandle, k.containerName, scPIN)
}

// CreateKey generates a new key using Golang crypto and returns both public and
// private key.
func (k *CAPIKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {

	if req.Name == "" {
		return nil, errors.Errorf("capi signing request must have a name")
	}

	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}

	if k.containerName = u.Get(ContainerNameArg); k.containerName == "" {
		// generate a uuid for the container name
		k.containerName, err = randutil.UUIDv4()
		if err != nil {
			return nil, fmt.Errorf("failed to generate uuid: %w", err)
		}
	}

	alg, ok := signatureAlgorithmMapping[req.SignatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm %v", req.SignatureAlgorithm)
	}

	kh, err := nCryptCreatePersistedKey(k.providerHandle, k.containerName, alg, AT_KEYEXCHANGE, 0)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create persisted key")
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

	// if supplied, set the smart card pin
	scPIN := u.Pin()

	//failover to pin set in kms instantiation
	if scPIN == "" {
		scPIN = k.pin
	}

	if scPIN != "" {
		err = nCryptSetProperty(kh, NCRYPT_PIN_PROPERTY, scPIN, 0)

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

	return &apiv1.CreateKeyResponse{
		Name:      uc,
		PublicKey: pub,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: uc,
		},
	}, nil
}

// GetPublicKey returns the public key from the file passed in the request name.
func (k *CAPIKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	var u *uri.URI

	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}

	if k.containerName = u.Get(ContainerNameArg); k.containerName == "" {
		return nil, fmt.Errorf("GetPublicKey %v not specified", ContainerNameArg)
	}

	kh, err := nCryptOpenKey(k.providerHandle, k.containerName, AT_KEYEXCHANGE, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to open key: %w", err)
	}

	defer nCryptFreeObject(kh)

	return getPublicKey(kh)
}

func (k *CAPIKMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI: %w", err)
	}

	var sha1Hash string
	if sha1Hash = u.Get(HashArg); sha1Hash == "" {
		return nil, fmt.Errorf("%v is required", HashArg)
	}

	// default to the user store
	var storeLocation string
	if storeLocation = u.Get(StoreLocationArg); storeLocation == "" {
		storeLocation = "user"
	}

	certStoreLocation := certStoreCurrentUser
	switch storeLocation {
	case "user":
		certStoreLocation = certStoreCurrentUser
	case "machine":
		certStoreLocation = certStoreLocalMachine
	default:
		return nil, fmt.Errorf("invalid cert store location %v", storeLocation)
	}

	var storeName string

	// default to storing in the 'My' store
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
		return nil, fmt.Errorf("CertOpenStore for the %v store %v returned: %w", storeLocation, storeName, err)
	}

	sha1Bytes, err := hex.DecodeString(sha1Hash)
	if err != nil {
		return nil, fmt.Errorf("sha1 must be in hex format: %w", err)
	}

	// create a CRYPT_INTEGER_BLOB -- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa381414(v=vs.85)
	hashBlob := struct {
		len  uint32
		hash uintptr
	}{
		len:  uint32(len(sha1Bytes)),
		hash: uintptr(unsafe.Pointer(&sha1Bytes[0])),
	}

	certHandle, err := findCertificateInStore(st,
		encodingX509ASN|encodingPKCS7,
		0,
		findHash,
		uintptr(unsafe.Pointer(&hashBlob)), nil)

	if err != nil {
		return nil, err
	}

	if certHandle == nil {
		return nil, fmt.Errorf("certificate with %v=%s not found", HashArg, sha1Hash)
	}

	defer windows.CertFreeCertificateContext(certHandle)

	var der []byte
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&der))
	slice.Data = uintptr(unsafe.Pointer(certHandle.EncodedCert))
	slice.Len = int(certHandle.Length)
	slice.Cap = int(certHandle.Length)
	x509Cert, err := x509.ParseCertificate(der)

	if err != nil {
		return nil, err
	}

	return x509Cert, nil
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

	certStoreLocation := certStoreCurrentUser
	switch storeLocation {
	case "user":
		certStoreLocation = certStoreCurrentUser
	case "machine":
		certStoreLocation = certStoreLocalMachine
	default:
		return fmt.Errorf("invalid cert store location %v", storeLocation)
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

	cryptFindCertificateKeyProvInfo(certContext) // TODO: not finding the associated private key is not a dealbreaker, but maybe a warning should be issued

	st, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocation,
		uintptr(unsafe.Pointer(wide(storeName))))
	if err != nil {
		return fmt.Errorf("CertOpenStore for the %v store %v returned: %w", storeLocation, storeName, err)
	}

	// Add the cert context to the system certificate store
	if err = windows.CertAddCertificateContextToStore(st, certContext, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore returned: %w", err)
	}

	return nil
}

type CAPISigner struct {
	algorithmGroup string
	providerHandle uintptr
	keyHandle      uintptr
	containerName  string
	PublicKey      crypto.PublicKey
}

func newCAPISigner(providerHandle uintptr, containerName string, pin string) (crypto.Signer, error) {
	kh, err := nCryptOpenKey(providerHandle, containerName, AT_KEYEXCHANGE, 0)
	if err != nil {
		return nil, fmt.Errorf("unable to open key: %w", err)
	}

	if pin != "" {
		err = nCryptSetProperty(kh, NCRYPT_PIN_PROPERTY, pin, 0)

		if err != nil {
			return nil, fmt.Errorf("unable to set key NCRYPT_PIN_PROPERTY: %w", err)
		}
	}

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
		providerHandle: providerHandle,
		keyHandle:      kh,
		containerName:  containerName,
		PublicKey:      pub,
	}

	return &signer, nil
}

func (s *CAPISigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {

	if _, isRSAPSS := opts.(*rsa.PSSOptions); isRSAPSS {
		return nil, fmt.Errorf("RSA-PSS signing is not supported")
	}

	switch s.algorithmGroup {
	case "ECDSA":
		signatureBytes, err := nCryptSignHash(s.keyHandle, digest, "")

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
		signatureBytes, err := nCryptSignHash(s.keyHandle, digest, hashAlg)

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
