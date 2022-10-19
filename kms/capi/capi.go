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
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
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
	PINArg           = "pin"
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

type CAPIKMS struct {
	providerName   string
	providerHandle uintptr
	containerName  string
}

func unmarshalRSA(buf []byte) (*rsa.PublicKey, error) {
	// BCRYPT_RSA_BLOB from bcrypt.h
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
	if n, err := r.Read(exp[8-header.PublicExpSize:]); n != int(header.PublicExpSize) || err != nil {
		return nil, fmt.Errorf("failed to read public exponent (%d, %v)", n, err)
	}

	mod := make([]byte, header.ModulusSize)
	if n, err := r.Read(mod); n != int(header.ModulusSize) || err != nil {
		return nil, fmt.Errorf("failed to read modulus (%d, %v)", n, err)
	}

	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(mod),
		E: int(binary.BigEndian.Uint64(exp)),
	}
	return pub, nil
}

func unmarshalECC(buf []byte, curve elliptic.Curve) (*ecdsa.PublicKey, error) {
	// BCRYPT_ECCKEY_BLOB from bcrypt.h
	header := struct {
		Magic uint32
		Key   uint32
	}{}

	r := bytes.NewReader(buf)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, err
	}

	keyX := make([]byte, header.Key)
	if n, err := r.Read(keyX); n != int(header.Key) || err != nil {
		return nil, fmt.Errorf("failed to read key X (%d, %v)", n, err)
	}

	keyY := make([]byte, header.Key)
	if n, err := r.Read(keyY); n != int(header.Key) || err != nil {
		return nil, fmt.Errorf("failed to read key Y (%d, %v)", n, err)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(keyX),
		Y:     new(big.Int).SetBytes(keyY),
	}
	return pub, nil
}

func getPublicKey(kh uintptr) (crypto.PublicKey, error) {
	algGroup, err := NCryptGetPropertyStr(kh, NCRYPT_ALGORITHM_GROUP_PROPERTY)
	if err != nil {
		return nil, errors.Wrap(err, "GetPublicKey unable to get NCRYPT_ALGORITHM_GROUP_PROPERTY")
	}

	var pub crypto.PublicKey
	switch algGroup {
	case "ECDSA":
		buf, err := NCryptExportKey(kh, BCRYPT_ECCPUBLIC_BLOB)
		if err != nil {
			return nil, fmt.Errorf("failed to export ECC public key: %v", err)
		}
		curveName, err := NCryptGetPropertyStr(kh, NCRYPT_ECC_CURVE_NAME_PROPERTY)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve ECC curve name: %v", err)
		}
		pub, err = unmarshalECC(buf, curveNames[curveName])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ECC public key: %v", err)
		}
	default:
		buf, err := NCryptExportKey(kh, BCRYPT_RSAPUBLIC_BLOB)
		if err != nil {
			return nil, fmt.Errorf("failed to export %v public key: %v", algGroup, err)
		}
		pub, err = unmarshalRSA(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal %v public key: %v", algGroup, err)
		}
	}

	return pub, nil
}

// New returns a new CAPIKMS.
func New(ctx context.Context, opts apiv1.Options) (*CAPIKMS, error) {
	var providerName string
	containerUUID, _ := uuid.NewRandom()
	containerName := containerUUID.String()

	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, err
		}

		if v := u.Get(ProviderNameArg); v != "" {
			providerName = v
		} else {
			providerName = "Microsoft Software Key Storage Provider"
		}
	}

	ph, err := NCryptOpenStorage(providerName)

	if err != nil {
		return nil, err
	}

	return &CAPIKMS{
		providerName:   providerName,
		providerHandle: ph,
		containerName:  containerName,
	}, nil
}

func init() {
	apiv1.Register(apiv1.CAPIKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

func (k *CAPIKMS) Close() error {
	if k.providerHandle != 0 {
		return NCryptFreeObject(k.providerHandle)
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

	scPIN := u.Get(PINArg)

	return NewCAPISigner(k.providerHandle, k.containerName, scPIN)
}

// CreateKey generates a new key using Golang crypto and returns both public and
// private key.
func (k *CAPIKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {

	if req.Name == "" {
		return nil, errors.Errorf("capi signing request must have a name")
	}

	var u *uri.URI

	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse URI")
	}

	if k.containerName = u.Get(ContainerNameArg); k.containerName == "" {
		// generate a uuid for the container name
		containerUUID, err := uuid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(err, "failed to generate uuid")
		}
		k.containerName = containerUUID.String()
	}

	alg, ok := signatureAlgorithmMapping[req.SignatureAlgorithm]

	if !ok {
		return nil, errors.Errorf("unsupported algorithm %v", req.SignatureAlgorithm)
	}

	kh, err := NCryptCreatePersistedKey(k.providerHandle, k.containerName, alg, AT_KEYEXCHANGE, 0)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create persisted key")
	}

	defer NCryptFreeObject(kh)

	if alg == "RSA" {
		err = NCryptSetProperty(kh, NCRYPT_LENGTH_PROPERTY, uint32(req.Bits), 0)

		if err != nil {
			return nil, errors.Wrap(err, "unable to set key NCRYPT_LENGTH_PROPERTY")
		}
	}

	// users can store the key as a machine key by passing in storelocation = machine
	if storeLocation := u.Get(StoreLocationArg); storeLocation == "machine" {
		err = NCryptSetProperty(kh, NCRYPT_KEY_TYPE_PROPERTY, NCRYPT_MACHINE_KEY_FLAG, 0)

		if err != nil {
			return nil, errors.Wrap(err, "unable to set key NCRYPT_KEY_TYPE_PROPERTY")
		}
	}

	// if supplied, set the smart card pin
	if scPIN := u.Get(PINArg); scPIN != "" {
		err = NCryptSetProperty(kh, NCRYPT_PIN_PROPERTY, scPIN, 0)

		if err != nil {
			return nil, errors.Wrap(err, "unable to set key NCRYPT_PIN_PROPERTY")
		}
	}

	err = NCryptFinalizeKey(kh, 0)
	if err != nil {
		return nil, errors.Wrap(err, "unable to finalize key")
	}

	uc, err := NCryptGetPropertyStr(kh, NCRYPT_UNIQUE_NAME_PROPERTY)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve key container")
	}

	pub, err := getPublicKey(kh)
	if err != nil {
		return nil, errors.Wrap(err, "unable to retrieve public key")
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
		return nil, errors.Wrap(err, "GetPublicKey failed to parse URI")
	}

	if k.containerName = u.Get(ContainerNameArg); k.containerName == "" {
		return nil, errors.Errorf("GetPublicKey %v not specified", ContainerNameArg)
	}

	kh, err := NCryptOpenKey(k.providerHandle, k.containerName, AT_KEYEXCHANGE, 0)
	if err != nil {
		return nil, errors.Wrap(err, "GetPublicKey unable to open key")
	}

	defer NCryptFreeObject(kh)

	return getPublicKey(kh)
}

func (k *CAPIKMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	u, err := uri.ParseWithScheme(Scheme, req.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse URI")
	}

	var sha1Hash string
	if sha1Hash = u.Get(HashArg); sha1Hash == "" {
		return nil, errors.Errorf("%v is required", HashArg)
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
		return nil, errors.Errorf("invalid cert store location %v", storeLocation)
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
		return nil, fmt.Errorf("CertOpenStore for the %v store %v returned: %v", storeLocation, storeName, err)
	}

	sha1Bytes, err := hex.DecodeString(sha1Hash)
	if err != nil {
		return nil, fmt.Errorf("sha1 must be in hex format: %v", err)
	}

	// create a CRYPT_INTEGER_BLOB -- https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa381414(v=vs.85)
	hashBlob := struct {
		len  uint32
		hash uintptr
	}{
		len:  uint32(len(sha1Bytes)),
		hash: uintptr(unsafe.Pointer(&sha1Bytes[0])),
	}

	certHandle, err := FindCertificateInStore(st,
		encodingX509ASN|encodingPKCS7,
		0,
		findHash,
		uintptr(unsafe.Pointer(&hashBlob)), nil)

	if err != nil {
		return nil, err
	}

	if certHandle == nil {
		return nil, errors.Errorf("certificate with %v=%s not found", HashArg, sha1Hash)
	}

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
		return errors.Wrap(err, "failed to parse URI")
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
		return errors.Errorf("invalid cert store location %v", storeLocation)
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
		return fmt.Errorf("CertCreateCertificateContext returned: %v", err)
	}
	defer windows.CertFreeCertificateContext(certContext)

	CryptFindCertificateKeyProvInfo(certContext) // TODO: not finding the associated private key is not a dealbreaker, but maybe a warning should be issued

	st, err := windows.CertOpenStore(
		certStoreProvSystem,
		0,
		0,
		certStoreLocation,
		uintptr(unsafe.Pointer(wide(storeName))))
	if err != nil {
		return fmt.Errorf("CertOpenStore for the %v store %v returned: %v", storeLocation, storeName, err)
	}

	// Add the cert context to the system certificate store
	if err = windows.CertAddCertificateContextToStore(st, certContext, windows.CERT_STORE_ADD_ALWAYS, nil); err != nil {
		return fmt.Errorf("CertAddCertificateContextToStore returned: %v", err)
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

func NewCAPISigner(providerHandle uintptr, containerName string, pin string) (crypto.Signer, error) {
	kh, err := NCryptOpenKey(providerHandle, containerName, AT_KEYEXCHANGE, 0)
	if err != nil {
		return nil, errors.Wrap(err, "unable to open key")
	}

	if pin != "" {
		err = NCryptSetProperty(kh, NCRYPT_PIN_PROPERTY, pin, 0)

		if err != nil {
			return nil, errors.Wrap(err, "unable to set key NCRYPT_PIN_PROPERTY")
		}
	}

	pub, err := getPublicKey(kh)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get public key")
	}

	algGroup, err := NCryptGetPropertyStr(kh, NCRYPT_ALGORITHM_GROUP_PROPERTY)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get NCRYPT_ALGORITHM_GROUP_PROPERTY")
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
	switch s.algorithmGroup {
	case "ECDSA":
		signatureBytes, err := NCryptSignHash(s.keyHandle, digest, "")

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
		signatureBytes, err := NCryptSignHash(s.keyHandle, digest, hashAlg)

		if err != nil {
			return nil, errors.Wrap(err, "NCryptSignHash failed")
		}

		return signatureBytes, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm group %v", s.algorithmGroup)
	}
}

func (s *CAPISigner) Public() crypto.PublicKey {
	return s.PublicKey
}
