//go:build cgo && !nopkcs11
// +build cgo,!nopkcs11

package pkcs11

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"strconv"
	"sync"

	"github.com/ThalesIgnite/crypto11"
	"github.com/pkg/errors"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
)

// Scheme is the scheme used in uris, the string "pkcs11".
const Scheme = string(apiv1.PKCS11)

// DefaultRSASize is the number of bits of a new RSA key if no size has been
// specified.
const DefaultRSASize = 3072

// P11 defines the methods on crypto11.Context that this package will use. This
// interface will be used for unit testing.
type P11 interface {
	FindKeyPair(id, label []byte) (crypto11.Signer, error)
	FindCertificate(id, label []byte, serial *big.Int) (*x509.Certificate, error)
	ImportCertificateWithAttributes(template crypto11.AttributeSet, certificate *x509.Certificate) error
	DeleteCertificate(id, label []byte, serial *big.Int) error
	GenerateRSAKeyPairWithAttributes(public, private crypto11.AttributeSet, bits int) (crypto11.SignerDecrypter, error)
	GenerateECDSAKeyPairWithAttributes(public, private crypto11.AttributeSet, curve elliptic.Curve) (crypto11.Signer, error)
	Close() error
}

var p11Configure = func(config *crypto11.Config) (P11, error) {
	return crypto11.Configure(config)
}

// PKCS11 is the implementation of a KMS using the PKCS #11 standard.
type PKCS11 struct {
	p11    P11
	closed sync.Once
}

// New returns a new PKCS#11 KMS. To initialize it, you need to provide a URI
// with the following format:
//
//   - pkcs11:token=smallstep?pin-value=password
//   - pkcs11:serial=1a2b3c4d5e6f?pin-source=/path/to/pin.txt
//   - pkcs11:slot-id=5?pin-value=password
//   - pkcs11:module-path=/path/to/module.so;token=smallstep?pin-value=password
//
// The scheme is "pkcs11"; "token", "serial", or "slot-id" defines the
// cryptographic device to use. "module-path" is the path of the PKCS#11 module
// to use. It will default to the proxy module of the p11-kit project if none is
// specified (p11-kit-proxy.so). "pin-value" provides the user's PIN, and
// "pin-source" defines a file that contains the PIN.
//
// A cryptographic key or object is identified by its "id" or "object"
// attributes. The "id" is the key identifier for the object, it's a hexadecimal
// string, and it will set the CKA_ID attribute of the object. The "object" is
// the name of the object, and it will set the CKA_LABEL attribute. Only one
// attribute is required to identify a key, but this package requires both to
// create a new key. The complete URI for a key looks like this:
//
//   - pkcs11:token=smallstep;id=0a10;object=ec-key?pin-value=password
//   - pkcs11:token=smallstep;id=%0a%10?pin-source=/path/to/pin.txt
//   - pkcs11:token=smallstep;object=ec-key?pin-value=password
func New(_ context.Context, opts apiv1.Options) (*PKCS11, error) {
	if opts.URI == "" {
		return nil, errors.New("kms uri is required")
	}

	var config crypto11.Config
	u, err := uri.ParseWithScheme(Scheme, opts.URI)
	if err != nil {
		return nil, err
	}

	config.TokenLabel = u.Get("token")
	config.TokenSerial = u.Get("serial")
	if v := u.Get("slot-id"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, errors.Wrap(err, "kms uri 'slot-id' is not valid")
		}
		config.SlotNumber = &n
	}

	// Get module or default to use p11-kit-proxy.so.
	//
	// pkcs11.New(module string) will use dlopen that will look for the
	// given library in the appropriate paths, so there's no need to provide
	// the full path.
	if config.Path = u.Get("module-path"); config.Path == "" {
		config.Path = defaultModule
	}

	config.Pin = u.Pin()
	if config.Pin == "" && opts.Pin != "" {
		config.Pin = opts.Pin
	}

	switch {
	case config.TokenLabel == "" && config.TokenSerial == "" && config.SlotNumber == nil:
		return nil, errors.New("kms uri 'token', 'serial' or 'slot-id' are required")
	case config.Pin == "":
		return nil, errors.New("kms 'pin' cannot be empty")
	case config.TokenLabel != "" && config.TokenSerial != "":
		return nil, errors.New("kms uri 'token' and 'serial' are mutually exclusive")
	case config.TokenLabel != "" && config.SlotNumber != nil:
		return nil, errors.New("kms uri 'token' and 'slot-id' are mutually exclusive")
	case config.TokenSerial != "" && config.SlotNumber != nil:
		return nil, errors.New("kms uri 'serial' and 'slot-id' are mutually exclusive")
	}

	p11, err := p11Configure(&config)
	if err != nil {
		return nil, errors.Wrap(err, "error initializing PKCS#11")
	}

	return &PKCS11{
		p11: p11,
	}, nil
}

// defaultModule defines the defaultModule used, in this case is the
// p11-kit-proxy provided by p11-kit.
var defaultModule = "p11-kit-proxy.so"

func init() {
	switch runtime.GOOS {
	case "darwin":
		defaultModule = "p11-kit-proxy.dylib"
	case "windows":
		defaultModule = "p11-kit-proxy.dll"
	}
	apiv1.Register(apiv1.PKCS11, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// GetPublicKey returns the public key stored in the object identified by the name URI.
func (k *PKCS11) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, errors.New("getPublicKeyRequest 'name' cannot be empty")
	}

	signer, err := findSigner(k.p11, req.Name)
	if err != nil {
		return nil, errors.Wrap(err, "getPublicKey failed")
	}

	return signer.Public(), nil
}

// CreateKey generates a new key in the PKCS#11 module and returns the public key.
func (k *PKCS11) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	switch {
	case req.Name == "":
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
	case req.Bits < 0:
		return nil, errors.New("createKeyRequest 'bits' cannot be negative")
	}

	signer, err := generateKey(k.p11, req)
	if err != nil {
		return nil, errors.Wrap(err, "createKey failed")
	}

	return &apiv1.CreateKeyResponse{
		Name:      req.Name,
		PublicKey: signer.Public(),
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: req.Name,
		},
	}, nil
}

// CreateSigner creates a signer using a key present in the PKCS#11 module.
func (k *PKCS11) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, errors.New("createSignerRequest 'signingKey' cannot be empty")
	}

	signer, err := findSigner(k.p11, req.SigningKey)
	if err != nil {
		return nil, errors.Wrap(err, "createSigner failed")
	}

	return signer, nil
}

// CreateDecrypter creates a decrypter using a key present in the PKCS#11
// module.
func (k *PKCS11) CreateDecrypter(req *apiv1.CreateDecrypterRequest) (crypto.Decrypter, error) {
	if req.DecryptionKey == "" {
		return nil, errors.New("createDecrypterRequest 'decryptionKey' cannot be empty")
	}

	signer, err := findSigner(k.p11, req.DecryptionKey)
	if err != nil {
		return nil, errors.Wrap(err, "createDecrypterRequest failed")
	}

	// Only RSA keys will implement the Decrypter interface.
	if _, ok := signer.Public().(*rsa.PublicKey); ok {
		if dec, ok := signer.(crypto.Decrypter); ok {
			return dec, nil
		}
	}
	return nil, errors.New("createDecrypterRequest failed: signer does not implement crypto.Decrypter")
}

// LoadCertificate implements kms.CertificateManager and loads a certificate
// from the YubiKey.
func (k *PKCS11) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	if req.Name == "" {
		return nil, errors.New("loadCertificateRequest 'name' cannot be nil")
	}
	cert, err := findCertificate(k.p11, req.Name)
	if err != nil {
		return nil, errors.Wrap(err, "loadCertificate failed")
	}
	return cert, nil
}

// StoreCertificate implements kms.CertificateManager and stores a certificate
// in the YubiKey.
func (k *PKCS11) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	switch {
	case req.Name == "":
		return errors.New("storeCertificateRequest 'name' cannot be empty")
	case req.Certificate == nil:
		return errors.New("storeCertificateRequest 'Certificate' cannot be nil")
	}

	id, object, err := parseObject(req.Name)
	if err != nil {
		return errors.Wrap(err, "storeCertificate failed")
	}

	// Enforce the use of both id and labels. This is not strictly necessary in
	// PKCS #11, but it's a good practice.
	if len(id) == 0 || len(object) == 0 {
		return errors.Errorf("key with uri %s is not valid, id and object are required", req.Name)
	}

	cert, err := k.p11.FindCertificate(id, object, nil)
	if err != nil {
		return errors.Wrap(err, "storeCertificate failed")
	}
	if cert != nil {
		return errors.Wrap(apiv1.AlreadyExistsError{
			Message: req.Name + " already exists",
		}, "storeCertificate failed")
	}

	// Import certificate with the necessary attributes.
	template, err := crypto11.NewAttributeSetWithIDAndLabel(id, object)
	if err != nil {
		return errors.Wrap(err, "storeCertificate failed")
	}
	if req.Extractable {
		if err := template.Set(crypto11.CkaExtractable, true); err != nil {
			return errors.Wrap(err, "storeCertificate failed")
		}
	}
	if err := k.p11.ImportCertificateWithAttributes(template, req.Certificate); err != nil {
		return errors.Wrap(err, "storeCertificate failed")
	}

	return nil
}

// DeleteKey is a utility function to delete a key given an uri.
func (k *PKCS11) DeleteKey(u string) error {
	id, object, err := parseObject(u)
	if err != nil {
		return errors.Wrap(err, "deleteKey failed")
	}
	signer, err := k.p11.FindKeyPair(id, object)
	if err != nil {
		return errors.Wrap(err, "deleteKey failed")
	}
	if signer == nil {
		return nil
	}
	if err := signer.Delete(); err != nil {
		return errors.Wrap(err, "deleteKey failed")
	}
	return nil
}

// DeleteCertificate is a utility function to delete a certificate given an uri.
func (k *PKCS11) DeleteCertificate(u string) error {
	id, object, err := parseObject(u)
	if err != nil {
		return errors.Wrap(err, "deleteCertificate failed")
	}
	if err := k.p11.DeleteCertificate(id, object, nil); err != nil {
		return errors.Wrap(err, "deleteCertificate failed")
	}
	return nil
}

// Close releases the connection to the PKCS#11 module.
func (k *PKCS11) Close() (err error) {
	k.closed.Do(func() {
		err = errors.Wrap(k.p11.Close(), "error closing pkcs#11 context")
	})
	return
}

func toByte(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func parseObject(rawuri string) ([]byte, []byte, error) {
	u, err := uri.ParseWithScheme(Scheme, rawuri)
	if err != nil {
		return nil, nil, err
	}
	id := u.GetEncoded("id")
	object := u.Get("object")
	if len(id) == 0 && object == "" {
		return nil, nil, errors.Errorf("key with uri %s is not valid, id or object are required", rawuri)
	}

	return id, toByte(object), nil
}

func generateKey(ctx P11, req *apiv1.CreateKeyRequest) (crypto11.Signer, error) {
	id, object, err := parseObject(req.Name)
	if err != nil {
		return nil, err
	}

	signer, err := ctx.FindKeyPair(id, object)
	if err != nil {
		return nil, err
	}
	if signer != nil {
		return nil, apiv1.AlreadyExistsError{
			Message: req.Name + " already exists",
		}
	}

	// Enforce the use of both id and labels. This is not strictly necessary in
	// PKCS #11, but it's a good practice.
	if len(id) == 0 || len(object) == 0 {
		return nil, errors.Errorf("key with uri %s is not valid, id and object are required", req.Name)
	}

	// Create template for public and private keys
	public, err := crypto11.NewAttributeSetWithIDAndLabel(id, object)
	if err != nil {
		return nil, err
	}
	private := public.Copy()
	if req.Extractable {
		if err := private.Set(crypto11.CkaExtractable, true); err != nil {
			return nil, err
		}
	}

	bits := req.Bits
	if bits == 0 {
		bits = DefaultRSASize
	}

	switch req.SignatureAlgorithm {
	case apiv1.UnspecifiedSignAlgorithm:
		return ctx.GenerateECDSAKeyPairWithAttributes(public, private, elliptic.P256())
	case apiv1.SHA256WithRSA, apiv1.SHA384WithRSA, apiv1.SHA512WithRSA:
		return ctx.GenerateRSAKeyPairWithAttributes(public, private, bits)
	case apiv1.SHA256WithRSAPSS, apiv1.SHA384WithRSAPSS, apiv1.SHA512WithRSAPSS:
		return ctx.GenerateRSAKeyPairWithAttributes(public, private, bits)
	case apiv1.ECDSAWithSHA256:
		return ctx.GenerateECDSAKeyPairWithAttributes(public, private, elliptic.P256())
	case apiv1.ECDSAWithSHA384:
		return ctx.GenerateECDSAKeyPairWithAttributes(public, private, elliptic.P384())
	case apiv1.ECDSAWithSHA512:
		return ctx.GenerateECDSAKeyPairWithAttributes(public, private, elliptic.P521())
	case apiv1.PureEd25519:
		return nil, fmt.Errorf("signature algorithm %s is not supported", req.SignatureAlgorithm)
	default:
		return nil, fmt.Errorf("signature algorithm %s is not supported", req.SignatureAlgorithm)
	}
}

func findSigner(ctx P11, rawuri string) (crypto11.Signer, error) {
	id, object, err := parseObject(rawuri)
	if err != nil {
		return nil, err
	}
	signer, err := ctx.FindKeyPair(id, object)
	if err != nil {
		return nil, errors.Wrapf(err, "error finding key with uri %s", rawuri)
	}
	if signer == nil {
		return nil, errors.Errorf("key with uri %s not found", rawuri)
	}
	return signer, nil
}

func findCertificate(ctx P11, rawuri string) (*x509.Certificate, error) {
	u, err := uri.ParseWithScheme(Scheme, rawuri)
	if err != nil {
		return nil, err
	}
	id, object, serial := u.GetEncoded("id"), u.Get("object"), u.Get("serial")
	if len(id) == 0 && object == "" && serial == "" {
		return nil, errors.Errorf("key with uri %s is not valid, id, object or serial are required", rawuri)
	}

	var serialNumber *big.Int
	if serial != "" {
		b, err := hex.DecodeString(serial)
		if err != nil {
			return nil, errors.Errorf("key with uri %s is not valid, failed to decode serial", rawuri)
		}
		serialNumber = new(big.Int).SetBytes(b)
	}

	cert, err := ctx.FindCertificate(id, toByte(object), serialNumber)
	if err != nil {
		return nil, errors.Wrapf(err, "error finding certificate with uri %s", rawuri)
	}
	if cert == nil {
		return nil, errors.Errorf("certificate with uri %s not found", rawuri)
	}
	return cert, nil
}

var _ apiv1.CertificateManager = (*PKCS11)(nil)
