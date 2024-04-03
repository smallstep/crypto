//go:build !notpmkms
// +build !notpmkms

package tpmkms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // required for Windows key ID calculation
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"go.step.sm/crypto/fingerprint"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/attestation"
	"go.step.sm/crypto/tpm/storage"
	"go.step.sm/crypto/tpm/tss2"
)

func init() {
	apiv1.Register(apiv1.TPMKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// Scheme is the scheme used in TPM KMS URIs, the string "tpmkms".
const Scheme = string(apiv1.TPMKMS)

const (
	// DefaultRSASize is the number of bits of a new RSA key if no size has been
	// specified. Whereas we're generally defaulting to 3072 bits for new RSA keys,
	// 2048 is used as the default for the TPMKMS, because we've observed the TPMs
	// we're testing with to be supporting this as the maximum RSA key size. We might
	// increase the default in the (near) future, but we want to be more confident
	// about the supported size for a specific TPM (model) in that case.
	DefaultRSASize = 2048
	// defaultRSAAKSize is the default number of bits for a new RSA Attestation
	// Key. It is currently set to 2048, because that's what's mentioned in the
	// TCG TPM specification and is used by the AK template in `go-attestation`.
	defaultRSAAKSize = 2048
)

// TPMKMS is a KMS implementation backed by a TPM.
type TPMKMS struct {
	tpm                              *tpm.TPM
	windowsCertificateManager        apiv1.CertificateManager
	windowsCertificateStoreLocation  string
	windowsCertificateStore          string
	windowsIntermediateStoreLocation string
	windowsIntermediateStore         string
	attestationCABaseURL             string
	attestationCARootFile            string
	attestationCAInsecure            bool
	permanentIdentifier              string
	identityRenewalPeriodPercentage  int64
	identityEarlyRenewalEnabled      bool
}

type algorithmAttributes struct {
	Type  string
	Curve int
}

var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]algorithmAttributes{
	apiv1.UnspecifiedSignAlgorithm: {"RSA", -1},
	apiv1.SHA256WithRSA:            {"RSA", -1},
	apiv1.SHA384WithRSA:            {"RSA", -1},
	apiv1.SHA512WithRSA:            {"RSA", -1},
	apiv1.SHA256WithRSAPSS:         {"RSA", -1},
	apiv1.SHA384WithRSAPSS:         {"RSA", -1},
	apiv1.SHA512WithRSAPSS:         {"RSA", -1},
	apiv1.ECDSAWithSHA256:          {"ECDSA", 256},
	apiv1.ECDSAWithSHA384:          {"ECDSA", 384},
	apiv1.ECDSAWithSHA512:          {"ECDSA", 521},
}

const (
	microsoftPCP                     = "Microsoft Platform Crypto Provider"
	defaultStoreLocation             = "user"
	defaultStore                     = "My"
	defaultIntermediateStoreLocation = "user"
	defaultIntermediateStore         = "CA" // TODO(hs): verify "CA" works for "machine" certs too
)

// New initializes a new KMS backed by a TPM.
//
// A new TPMKMS can be initialized with a configuration by providing
// a URI in the options:
//
//	New(ctx, &apiv1.Options{
//	    URI: tpmkms:device=/dev/tpmrm0;storage-directory=/path/to/tpmstorage/directory
//	})
//
// It's also possible to set the storage directory as follows:
//
//	New(ctx, &apiv1.Options{
//	    URI: tpmkms:device=/dev/tpmrm0
//		StorageDirectory: /path/to/tpmstorage/directory
//	})
//
// The default storage location for serialized TPM objects when
// an instance of TPMKMS is created, is the relative path "tpm".
//
// The system default TPM device will be used when not configured. A
// specific TPM device can be selected by setting the device:
//
//	tpmkms:device=/dev/tpmrm0
//
// By default newly created TPM objects won't be persisted, so can't
// be readily used. The location for storage can be set using
// storage-directory:
//
//	tpmkms:storage-directory=/path/to/tpmstorage/directory
//
// On Windows the TPMKMS implementation has an option to use the native
// certificate stores for certificate storage and retrieval instead of
// using the storage directory for those. TPM keys will still be persisted
// to the storage directory, because that's how the KMS keeps track of which
// keys it manages, but it'll use the Windows certificate stores for
// operations that involve certificates for TPM keys. Use the "enable-cng"
// option to enable this optional integration:
//
//	tpmkms:enable-cng=true
//
// If the CryptoAPI Next Generation (CNG) integration is enabled, the TPMKMS
// will use an instance of the CAPIKMS to manage certificates. It'll use the
// the "Personal" ("My") user certificate store by default. A different location
// and store to be used for all operations against the TPMKMS can be defined as
// follows:
//
//	tpmkms:store-location=machine;store=CA
//
// The location and store to use can be overridden for a specific operation
// against a TPMKMS instance, if required. It's not possible to change the crypto
// provider to user; that will always be the "Microsoft Platform Crypto Provider"
//
// For operations that involve certificate chains, it's possible to set the
// intermediate CA store location and store name at initialization time. The
// same options can be used for a specific operation, if needed. By default the
// "CA" user certificate store is used.
//
// tpmkms:intermediate-store-location=machine;intermediate-store=CustomCAStore
//
// For attestation use cases that involve the Smallstep Attestation CA
// or a compatible one, several properties can be set. The following
// specify the Attestation CA base URL, the path to a bundle of root CAs
// to trust when setting up a TLS connection to the Attestation CA and
// disable TLS certificate validation, respectively.
//
//	tpmkms:attestation-ca-url=https://my.attestation.ca
//	tpmkms:attestation-ca-root=/path/to/trusted/roots.pem
//	tpmkms:attestation-ca-insecure=true
//
// The system may not always have a PermanentIdentifier assigned, so
// when initializing the TPMKMS, it's possible to set this value:
//
//	tpmkms:permanent-identifier=<some-unique-identifier>
//
// By default, an AK (identity) certificate will be renewed early
// if it's expiring soon. The default certificate lifetime is 60%,
// meaning that the renewal for the AK certificate will be kicked
// off when it's past 60% of its lifetime. It's possible to disable
// early renewal by setting disable-early-renewal to true:
//
//	tpmkms:disable-early-renewal=true
//
// The default lifetime percentage can be changed by setting
// renewal-percentage:
//
//	tpmkms:renewal-percentage=70
//
// Attestation support in the TPMKMS is considered EXPERIMENTAL. It
// is expected that there will be changes to the configuration that
// be provided and the attestation flow.
//
// The TPMKMS implementation is backed by an instance of the TPM from
// the `tpm` package. If the TPMKMS operations aren't sufficient for
// your use case, use a tpm.TPM instance instead.
func New(ctx context.Context, opts apiv1.Options) (kms *TPMKMS, err error) {
	kms = &TPMKMS{
		identityEarlyRenewalEnabled:     true,
		identityRenewalPeriodPercentage: 60, // default to AK certificate renewal at 60% of lifetime
	}
	storageDirectory := "tpm" // store TPM objects in a relative tpm directory by default.
	if opts.StorageDirectory != "" {
		storageDirectory = opts.StorageDirectory
	}
	tpmOpts := []tpm.NewTPMOption{tpm.WithStore(storage.NewDirstore(storageDirectory))}
	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %q as URI: %w", opts.URI, err)
		}
		if device := u.Get("device"); device != "" {
			tpmOpts = append(tpmOpts, tpm.WithDeviceName(device))
		}
		if storageDirectory := u.Get("storage-directory"); storageDirectory != "" {
			tpmOpts = append(tpmOpts, tpm.WithStore(storage.NewDirstore(storageDirectory)))
		}
		kms.attestationCABaseURL = u.Get("attestation-ca-url")
		kms.attestationCARootFile = u.Get("attestation-ca-root")
		kms.attestationCAInsecure = u.GetBool("attestation-ca-insecure")
		kms.permanentIdentifier = u.Get("permanent-identifier") // TODO(hs): determine if this is needed
		kms.identityEarlyRenewalEnabled = !u.GetBool("disable-early-renewal")
		if percentage := u.GetInt("renewal-percentage"); percentage != nil {
			if *percentage < 1 || *percentage > 100 {
				return nil, fmt.Errorf("renewal percentage must be between 1 and 100; got %d", *percentage)
			}
			kms.identityRenewalPeriodPercentage = *percentage
		}

		// opt-in for enabling CAPI integration on Windows for certificate
		// management. This will result in certificates being stored to or
		// retrieved from the Windows certificate stores.
		enableCNG := u.GetBool("enable-cng") // TODO(hs): maybe change the option flag or make this the default on Windows
		if enableCNG && runtime.GOOS != "windows" {
			return nil, fmt.Errorf(`"enable-cng" is not supported on %s`, runtime.GOOS)
		}

		if enableCNG {
			fn, ok := apiv1.LoadKeyManagerNewFunc(apiv1.CAPIKMS)
			if !ok {
				name := filepath.Base(os.Args[0])
				return nil, fmt.Errorf(`unsupported KMS type "capi": %s is compiled without Microsoft CryptoAPI Next Generation (CNG) support`, name)
			}
			km, err := fn(ctx, apiv1.Options{
				Type: apiv1.CAPIKMS,
				URI:  uri.New("capi", url.Values{"provider": []string{microsoftPCP}}).String(),
			})
			if err != nil {
				return nil, fmt.Errorf("failed creating CAPIKMS instance: %w", err)
			}
			kms.windowsCertificateManager, ok = km.(apiv1.CertificateManager)
			if !ok {
				return nil, fmt.Errorf("unexpected type %T; expected apiv1.CertificateManager", km)
			}
			kms.windowsCertificateStoreLocation = defaultStoreLocation
			if storeLocation := u.Get("store-location"); storeLocation != "" {
				kms.windowsCertificateStoreLocation = storeLocation
			}
			kms.windowsCertificateStore = defaultStore
			if store := u.Get("store"); store != "" {
				kms.windowsCertificateStore = store
			}
			kms.windowsIntermediateStoreLocation = defaultIntermediateStoreLocation
			if intermediateStoreLocation := u.Get("intermediate-store-location"); intermediateStoreLocation != "" {
				kms.windowsIntermediateStoreLocation = intermediateStoreLocation
			}
			kms.windowsIntermediateStore = defaultIntermediateStore
			if intermediateStore := u.Get("intermediate-store"); intermediateStore != "" {
				kms.windowsIntermediateStore = intermediateStore
			}
		}

		// TODO(hs): support a mode in which the TPM storage doesn't rely on JSON on Windows
		// at all, but directly feeds into OS native storage? Some operations can be NOOPs, such
		// as the ones that create AKs and keys. Is all of the data available in the keys stored
		// with Windows, incl. the attestation certification?
	}

	kms.tpm, err = tpm.New(tpmOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed creating new TPM: %w", err)
	}

	return
}

// usesWindowsCertificateStore is a helper method that indicates whether
// the TPMKMS should use the Windows certificate stores for certificate
// operations.
func (k *TPMKMS) usesWindowsCertificateStore() bool {
	return k.windowsCertificateManager != nil
}

// CreateKey generates a new key in the TPM KMS and returns the public key.
//
// The `name` in the [apiv1.CreateKeyRequest] can be used to specify
// some key properties. These are as follows:
//
//   - name=<name>: specify the name to identify the key with
//   - ak=true: if set to true, an Attestation Key (AK) will be created instead of an application key
//   - tss2=true: is set to true, the PrivateKey response will contain a [tss2.TPMKey].
//   - attest-by=<akName>: attest an application key at creation time with the AK identified by `akName`
//   - qualifying-data=<random>: hexadecimal coded binary data that can be used to guarantee freshness when attesting creation of a key
//
// Some examples usages:
//
// Create an application key, without attesting it:
//
//	tpmkms:name=my-key
//
// Create an Attestation Key (AK):
//
//	tpmkms:name=my-ak;ak=true
//
// Create an application key, attested by `my-ak` with "1234" as the Qualifying Data:
//
//	tpmkms:name=my-attested-key;attest-by=my-ak;qualifying-data=61626364
func (k *TPMKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	switch {
	case req.Name == "":
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
	case req.Bits < 0:
		return nil, errors.New("createKeyRequest 'bits' cannot be negative")
	}

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	v, ok := signatureAlgorithmMapping[req.SignatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("TPMKMS does not support signature algorithm %q", req.SignatureAlgorithm)
	}

	if properties.ak && v.Type == "ECDSA" {
		return nil, errors.New("AKs must be RSA keys")
	}

	if properties.ak && req.Bits != 0 && req.Bits != defaultRSAAKSize { // 2048
		return nil, fmt.Errorf("creating %d bit AKs is not supported; AKs must be RSA 2048 bits", req.Bits)
	}

	size := DefaultRSASize // defaults to 2048
	if req.Bits > 0 {
		size = req.Bits
	}

	if v.Type == "ECDSA" {
		size = v.Curve
	}

	ctx := context.Background()

	var privateKey any
	if properties.ak {
		ak, err := k.tpm.CreateAK(ctx, properties.name) // NOTE: size is never passed for AKs; it's hardcoded to 2048 in lower levels.
		if err != nil {
			if errors.Is(err, tpm.ErrExists) {
				return nil, apiv1.AlreadyExistsError{Message: err.Error()}
			}
			return nil, fmt.Errorf("failed creating AK: %w", err)
		}

		if properties.tss2 {
			tpmKey, err := ak.ToTSS2(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed exporting AK to TSS2: %w", err)
			}
			privateKey = tpmKey
		}

		createdAKURI := fmt.Sprintf("tpmkms:name=%s;ak=true", ak.Name())
		return &apiv1.CreateKeyResponse{
			Name:       createdAKURI,
			PublicKey:  ak.Public(),
			PrivateKey: privateKey,
		}, nil
	}

	var key *tpm.Key
	if properties.attestBy != "" {
		config := tpm.AttestKeyConfig{
			Algorithm:      v.Type,
			Size:           size,
			QualifyingData: properties.qualifyingData,
		}
		key, err = k.tpm.AttestKey(ctx, properties.attestBy, properties.name, config)
		if err != nil {
			if errors.Is(err, tpm.ErrExists) {
				return nil, apiv1.AlreadyExistsError{Message: err.Error()}
			}
			return nil, fmt.Errorf("failed creating attested key: %w", err)
		}
	} else {
		config := tpm.CreateKeyConfig{
			Algorithm: v.Type,
			Size:      size,
		}
		key, err = k.tpm.CreateKey(ctx, properties.name, config)
		if err != nil {
			if errors.Is(err, tpm.ErrExists) {
				return nil, apiv1.AlreadyExistsError{Message: err.Error()}
			}
			return nil, fmt.Errorf("failed creating key: %w", err)
		}
	}

	if properties.tss2 {
		tpmKey, err := key.ToTSS2(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed exporting key to TSS2: %w", err)
		}
		privateKey = tpmKey
	}

	signer, err := key.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting signer for key: %w", err)
	}

	createdKeyURI := fmt.Sprintf("tpmkms:name=%s", key.Name())
	if properties.attestBy != "" {
		createdKeyURI = fmt.Sprintf("%s;attest-by=%s", createdKeyURI, key.AttestedBy())
	}

	return &apiv1.CreateKeyResponse{
		Name:       createdKeyURI,
		PublicKey:  signer.Public(),
		PrivateKey: privateKey,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: createdKeyURI,
			Signer:     signer,
		},
	}, nil
}

// CreateSigner creates a signer using a key present in the TPM KMS.
//
// The `signingKey` in the [apiv1.CreateSignerRequest] can be used to specify
// some key properties. These are as follows:
//
//   - name=<name>: specify the name to identify the key with
//   - path=<file>: specify the TSS2 PEM file to use
func (k *TPMKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.Signer != nil {
		return req.Signer, nil
	}

	var pemBytes []byte

	switch {
	case req.SigningKey != "":
		properties, err := parseNameURI(req.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %q: %w", req.SigningKey, err)
		}
		if properties.ak {
			return nil, fmt.Errorf("signing with an AK currently not supported")
		}

		switch {
		case properties.name != "":
			ctx := context.Background()
			key, err := k.tpm.GetKey(ctx, properties.name)
			if err != nil {
				return nil, err
			}
			signer, err := key.Signer(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed getting signer for key %q: %w", properties.name, err)
			}
			return signer, nil
		case properties.path != "":
			if pemBytes, err = os.ReadFile(properties.path); err != nil {
				return nil, fmt.Errorf("failed reading key from %q: %w", properties.path, err)
			}
		default:
			return nil, fmt.Errorf("failed parsing %q: name and path cannot be empty", req.SigningKey)
		}
	case len(req.SigningKeyPEM) > 0:
		pemBytes = req.SigningKeyPEM
	default:
		return nil, errors.New("createSignerRequest 'signingKey' and 'signingKeyPEM' cannot be empty")
	}

	// Create a signer from a TSS2 PEM block
	key, err := parseTSS2(pemBytes)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	signer, err := tpm.CreateTSS2Signer(ctx, k.tpm, key)
	if err != nil {
		return nil, fmt.Errorf("failed getting signer for TSS2 PEM: %w", err)
	}
	return signer, nil
}

// GetPublicKey returns the public key present in the TPM KMS.
//
// The `name` in the [apiv1.GetPublicKeyRequest] can be used to specify some key
// properties. These are as follows:
//
//   - name=<name>: specify the name to identify the key with
//   - ak=true: if set to true, an Attestation Key (AK) will be read instead of an application key
//   - path=<file>: specify the TSS2 PEM file to read from
func (k *TPMKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, errors.New("getPublicKeyRequest 'name' cannot be empty")
	}

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	ctx := context.Background()
	switch {
	case properties.name != "":
		if properties.ak {
			ak, err := k.tpm.GetAK(ctx, properties.name)
			if err != nil {
				return nil, err
			}
			akPub := ak.Public()
			if akPub == nil {
				return nil, errors.New("failed getting AK public key")
			}
			return akPub, nil
		}

		key, err := k.tpm.GetKey(ctx, properties.name)
		if err != nil {
			return nil, err
		}

		signer, err := key.Signer(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed getting signer for key %q: %w", properties.name, err)
		}

		return signer.Public(), nil
	case properties.path != "":
		pemBytes, err := os.ReadFile(properties.path)
		if err != nil {
			return nil, fmt.Errorf("failed reading key from %q: %w", properties.path, err)
		}
		key, err := parseTSS2(pemBytes)
		if err != nil {
			return nil, err
		}
		pub, err := key.Public()
		if err != nil {
			return nil, fmt.Errorf("error decoding public key from %q: %w", properties.path, err)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("failed parsing %q: name and path cannot be empty", req.Name)
	}
}

// LoadCertificate loads the certificate for the key identified by name from the TPMKMS.
func (k *TPMKMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (cert *x509.Certificate, err error) {
	if req.Name == "" {
		return nil, errors.New("loadCertificateRequest 'name' cannot be empty")
	}

	chain, err := k.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{Name: req.Name})
	if err != nil {
		return nil, err
	}

	return chain[0], nil
}

// LoadCertificateChain loads the certificate chain for the key identified by
// name from the TPMKMS.
func (k *TPMKMS) LoadCertificateChain(req *apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	if req.Name == "" {
		return nil, errors.New("loadCertificateChainRequest 'name' cannot be empty")
	}

	if k.usesWindowsCertificateStore() {
		chain, err := k.loadCertificateChainFromWindowsCertificateStore(&apiv1.LoadCertificateRequest{
			Name: req.Name,
		})
		if err != nil {
			return nil, fmt.Errorf("failed loading certificate chain using Windows platform cryptography provider: %w", err)
		}
		return chain, nil
	}

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	ctx := context.Background()
	var chain []*x509.Certificate
	if properties.ak {
		ak, err := k.tpm.GetAK(ctx, properties.name)
		if err != nil {
			return nil, err
		}
		chain = ak.CertificateChain()
	} else {
		key, err := k.tpm.GetKey(ctx, properties.name)
		if err != nil {
			return nil, err
		}
		chain = key.CertificateChain()
	}

	if len(chain) == 0 {
		return nil, fmt.Errorf("failed getting certificate chain for %q: no certificate chain stored", properties.name)
	}

	return chain, nil
}

const (
	// maximumIterations is the maximum number of times for the recursive
	// intermediate CA lookup loop.
	maximumIterations = 10
)

func (k *TPMKMS) loadCertificateChainFromWindowsCertificateStore(req *apiv1.LoadCertificateRequest) ([]*x509.Certificate, error) {
	pub, err := k.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: req.Name,
	})
	if err != nil {
		return nil, fmt.Errorf("failed retrieving public key: %w", err)
	}

	o, err := parseNameURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	location := k.windowsCertificateStoreLocation
	if o.storeLocation != "" {
		location = o.storeLocation
	}
	store := k.windowsCertificateStore
	if o.store != "" {
		store = o.store
	}

	subjectKeyID, err := generateWindowsSubjectKeyID(pub)
	if err != nil {
		return nil, fmt.Errorf("failed generating subject key id: %w", err)
	}

	cert, err := k.windowsCertificateManager.LoadCertificate(&apiv1.LoadCertificateRequest{
		Name: fmt.Sprintf("capi:key-id=%s;store-location=%s;store=%s;", subjectKeyID, location, store),
	})
	if err != nil {
		return nil, fmt.Errorf("failed retrieving certificate using Windows platform cryptography provider: %w", err)
	}

	intermediateCAStoreLocation := k.windowsIntermediateStoreLocation
	if o.intermediateStoreLocation != "" {
		intermediateCAStoreLocation = o.intermediateStoreLocation
	}

	intermediateCAStore := k.windowsIntermediateStore
	if o.intermediateStore != "" {
		intermediateCAStore = o.intermediateStore
	}

	chain := []*x509.Certificate{cert}
	child := cert
	for i := 0; i < maximumIterations; i++ { // loop a maximum number of times
		authorityKeyID := hex.EncodeToString(child.AuthorityKeyId)
		parent, err := k.windowsCertificateManager.LoadCertificate(&apiv1.LoadCertificateRequest{
			Name: fmt.Sprintf("capi:key-id=%s;store-location=%s;store=%s", authorityKeyID, intermediateCAStoreLocation, intermediateCAStore),
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

// StoreCertificate stores the certificate for the key identified by name to the TPMKMS.
func (k *TPMKMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	switch {
	case req.Name == "":
		return errors.New("storeCertificateRequest 'name' cannot be empty")
	case req.Certificate == nil:
		return errors.New("storeCertificateRequest 'certificate' cannot be empty")
	}

	return k.StoreCertificateChain(&apiv1.StoreCertificateChainRequest{Name: req.Name, CertificateChain: []*x509.Certificate{req.Certificate}})
}

// StoreCertificateChain stores the certificate for the key identified by name to the TPMKMS.
func (k *TPMKMS) StoreCertificateChain(req *apiv1.StoreCertificateChainRequest) error {
	switch {
	case req.Name == "":
		return errors.New("storeCertificateChainRequest 'name' cannot be empty")
	case len(req.CertificateChain) == 0:
		return errors.New("storeCertificateChainRequest 'certificateChain' cannot be empty")
	}

	if k.usesWindowsCertificateStore() {
		if err := k.storeCertificateChainToWindowsCertificateStore(&apiv1.StoreCertificateChainRequest{
			Name:             req.Name,
			CertificateChain: req.CertificateChain,
		}); err != nil {
			return fmt.Errorf("failed storing certificate chain using Windows platform cryptography provider: %w", err)
		}

		return nil
	}

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	ctx := context.Background()
	if properties.ak {
		ak, err := k.tpm.GetAK(ctx, properties.name)
		if err != nil {
			return err
		}
		err = ak.SetCertificateChain(ctx, req.CertificateChain)
		if err != nil {
			return fmt.Errorf("failed storing certificate for AK %q: %w", properties.name, err)
		}
	} else {
		key, err := k.tpm.GetKey(ctx, properties.name)
		if err != nil {
			return err
		}

		err = key.SetCertificateChain(ctx, req.CertificateChain)
		if err != nil {
			return fmt.Errorf("failed storing certificate for key %q: %w", properties.name, err)
		}
	}

	return nil
}

func (k *TPMKMS) storeCertificateChainToWindowsCertificateStore(req *apiv1.StoreCertificateChainRequest) error {
	o, err := parseNameURI(req.Name)
	if err != nil {
		return fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	location := k.windowsCertificateStoreLocation
	if o.storeLocation != "" {
		location = o.storeLocation
	}
	store := k.windowsCertificateStore
	if o.store != "" {
		store = o.store
	}

	leaf := req.CertificateChain[0]
	fp, err := fingerprint.New(leaf.Raw, crypto.SHA1, fingerprint.HexFingerprint)
	if err != nil {
		return fmt.Errorf("failed calculating certificate SHA1 fingerprint: %w", err)
	}

	if err := k.windowsCertificateManager.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name:        fmt.Sprintf("capi:sha1=%s;store-location=%s;store=%s;", fp, location, store),
		Certificate: leaf,
	}); err != nil {
		return fmt.Errorf("failed storing certificate using Windows platform cryptography provider: %w", err)
	}

	if len(req.CertificateChain) == 1 {
		// no certificate chain; return early
		return nil
	}

	intermediateCAStoreLocation := k.windowsIntermediateStoreLocation
	if o.intermediateStoreLocation != "" {
		intermediateCAStoreLocation = o.intermediateStoreLocation
	}

	intermediateCAStore := k.windowsIntermediateStore
	if o.intermediateStore != "" {
		intermediateCAStore = o.intermediateStore
	}

	for _, c := range req.CertificateChain[1:] {
		if err := validateIntermediateCertificate(c); err != nil {
			return fmt.Errorf("invalid intermediate certificate provided in chain: %w", err)
		}
		if err := k.storeIntermediateToWindowsCertificateStore(c, intermediateCAStoreLocation, intermediateCAStore); err != nil {
			return fmt.Errorf("failed storing intermediate certificate using Windows platform cryptography provider: %w", err)
		}
	}

	return nil
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

func (k *TPMKMS) storeIntermediateToWindowsCertificateStore(c *x509.Certificate, storeLocation, store string) error {
	fp, err := fingerprint.New(c.Raw, crypto.SHA1, fingerprint.HexFingerprint)
	if err != nil {
		return fmt.Errorf("failed calculating certificate SHA1 fingerprint: %w", err)
	}

	if err := k.windowsCertificateManager.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name:        fmt.Sprintf("capi:sha1=%s;store-location=%s;store=%s;skip-find-certificate-key=true", fp, storeLocation, store),
		Certificate: c,
	}); err != nil {
		return err
	}

	return nil
}

// attestationClient is a wrapper for [attestation.Client], containing
// all of the required references to perform attestation against the
// Smallstep Attestation CA.
type attestationClient struct {
	c  *attestation.Client
	t  *tpm.TPM
	ek *tpm.EK
	ak *tpm.AK
}

// newAttestorClient creates a new [attestationClient], wrapping references
// to the [tpm.TPM] instance, the EK and the AK to use when attesting.
func (k *TPMKMS) newAttestorClient(ek *tpm.EK, ak *tpm.AK) (*attestationClient, error) {
	if k.attestationCABaseURL == "" {
		return nil, errors.New("failed creating attestation client: attestation CA base URL must not be empty")
	}
	// prepare a client to perform attestation with an Attestation CA
	attestationClientOptions := []attestation.Option{attestation.WithRootsFile(k.attestationCARootFile)}
	if k.attestationCAInsecure {
		attestationClientOptions = append(attestationClientOptions, attestation.WithInsecure())
	}
	client, err := attestation.NewClient(k.attestationCABaseURL, attestationClientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed creating attestation client: %w", err)
	}
	return &attestationClient{
		c:  client,
		t:  k.tpm,
		ek: ek,
		ak: ak,
	}, nil
}

// Attest implements the [apiv1.AttestationClient] interface, calling into the
// underlying [attestation.Client] to perform an attestation flow with the
// Smallstep Attestation CA.
func (ac *attestationClient) Attest(ctx context.Context) ([]*x509.Certificate, error) {
	return ac.c.Attest(ctx, ac.t, ac.ek, ac.ak)
}

// CreateAttestation implements the [apiv1.Attester] interface for the TPMKMS. It
// can be used to request the required information to verify that an application
// key was created in and by a specific TPM.
//
// It is expected that an application key has been attested at creation time by
// an attestation key (AK) before calling this method. An error will be returned
// otherwise.
//
// The response will include an attestation key (AK) certificate (chain) issued
// to the AK that was used to certify creation of the (application) key, as well
// as the key certification parameters at the time of key creation. Together these
// can be used by a relying party to attest that the key was created by a specific
// TPM.
//
// If no valid AK certificate is available when calling CreateAttestation, an
// enrolment with an instance of the Smallstep Attestation CA is performed. This
// will use the TPM Endorsement Key and the AK as inputs. The Attestation CA will
// return an AK certificate chain on success.
//
// When CreateAttestation is called for an AK, the AK certificate chain will be
// returned. Currently no AK creation parameters are returned.
func (k *TPMKMS) CreateAttestation(req *apiv1.CreateAttestationRequest) (*apiv1.CreateAttestationResponse, error) {
	if req.Name == "" {
		return nil, errors.New("createAttestationRequest 'name' cannot be empty")
	}

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	ctx := context.Background()
	eks, err := k.tpm.GetEKs(ctx) // TODO(hs): control the EK used as the caller of this method?
	if err != nil {
		return nil, fmt.Errorf("failed getting EKs: %w", err)
	}
	ek := getPreferredEK(eks)
	ekPublic := ek.Public()
	ekKeyID, err := generateKeyID(ekPublic)
	if err != nil {
		return nil, fmt.Errorf("failed getting EK public key ID: %w", err)
	}
	ekKeyURL := ekURL(ekKeyID)
	permanentIdentifier := ekKeyURL.String()

	// check if the derived EK URI fingerprint representation matches the provided
	// permanent identifier value. The current implementation requires the EK URI to
	// be used as the AK identity, so an error is returned if there's no match. This
	// could be changed in the future, so that another attestation flow takes place,
	// instead, for example.
	if k.permanentIdentifier != "" && permanentIdentifier != k.permanentIdentifier {
		return nil, fmt.Errorf("the provided permanent identifier %q does not match the EK URL %q", k.permanentIdentifier, permanentIdentifier)
	}

	var key *tpm.Key
	akName := properties.name
	if !properties.ak {
		key, err = k.tpm.GetKey(ctx, properties.name)
		if err != nil {
			return nil, err
		}
		if !key.WasAttested() {
			return nil, fmt.Errorf("key %q was not attested", key.Name())
		}
		akName = key.AttestedBy()
	}

	ak, err := k.tpm.GetAK(ctx, akName)
	if err != nil {
		return nil, err
	}

	// check if a (valid) AK certificate (chain) is available. Perform attestation flow
	// otherwise. If an AK certificate is available, but not considered valid, e.g. due
	// to it not having the right identity, a new attestation flow will be performed and
	// the old certificate (chain) will be overwritten with the result of that flow.
	if err := k.hasValidIdentity(ak, ekKeyURL); err != nil {
		var ac apiv1.AttestationClient
		if req.AttestationClient != nil {
			// TODO(hs): check if it makes sense to have this; it doesn't capture all
			// behavior of the built-in attestorClient, but at least it does provide
			// a basic extension point for other ways of performing attestation that
			// might be useful for testing or attestation flows against other systems.
			// For it to be truly useful, the logic for determining the AK identity
			// would have to be updated too, though.
			ac = req.AttestationClient
		} else {
			ac, err = k.newAttestorClient(ek, ak)
			if err != nil {
				return nil, fmt.Errorf("failed creating attestor client: %w", err)
			}
		}
		// perform the attestation flow with a (remote) attestation CA
		akChain, err := ac.Attest(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed performing AK attestation: %w", err)
		}
		// store the result with the AK, so that it can be reused for future
		// attestations.
		if err := ak.SetCertificateChain(ctx, akChain); err != nil {
			return nil, fmt.Errorf("failed storing AK certificate chain: %w", err)
		}
	}

	// when a new certificate was issued for the AK, it is possible the
	// certificate that was issued doesn't include the expected and/or required
	// identity, so this is checked before continuing.
	if err := k.hasValidIdentity(ak, ekKeyURL); err != nil {
		return nil, fmt.Errorf("AK certificate (chain) not valid for EK %q: %w", ekKeyURL, err)
	}

	akChain := ak.CertificateChain()

	if properties.ak {
		akPub := ak.Public()
		if akPub == nil {
			return nil, fmt.Errorf("failed getting AK public key")
		}
		// TODO(hs): decide if we want/need to return these; their purpose is slightly
		// different from the key certification parameters.
		_, err = ak.AttestationParameters(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed getting AK attestation parameters: %w", err)
		}
		return &apiv1.CreateAttestationResponse{
			Certificate:         akChain[0], // certificate for the AK
			CertificateChain:    akChain,    // chain for the AK, including the leaf
			PublicKey:           akPub,      // returns the public key of the attestation key
			PermanentIdentifier: permanentIdentifier,
		}, nil
	}

	signer, err := key.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting signer for key %q: %w", properties.name, err)
	}

	params, err := key.CertificationParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting key certification parameters for %q: %w", key.Name(), err)
	}

	// prepare the response to return
	akCert := akChain[0]
	return &apiv1.CreateAttestationResponse{
		Certificate:      akCert,          // certificate for the AK that attested the key
		CertificateChain: akChain,         // chain for the AK that attested the key, including the leaf
		PublicKey:        signer.Public(), // returns the public key of the attested key
		CertificationParameters: &apiv1.CertificationParameters{ // key certification parameters
			Public:            params.Public,
			CreateData:        params.CreateData,
			CreateAttestation: params.CreateAttestation,
			CreateSignature:   params.CreateSignature,
		},
		PermanentIdentifier: permanentIdentifier, // NOTE: should always match the valid value of the AK identity (for now)
	}, nil
}

// Close releases the connection to the TPM.
func (k *TPMKMS) Close() (err error) {
	return
}

// getPreferredEK returns the first RSA TPM EK found. If no RSA
// EK exists, it returns the first ECDSA EK found.
func getPreferredEK(eks []*tpm.EK) (ek *tpm.EK) {
	var fallback *tpm.EK
	for _, ek = range eks {
		if _, isRSA := ek.Public().(*rsa.PublicKey); isRSA {
			return
		}
		if fallback == nil {
			fallback = ek
		}
	}
	return fallback
}

// hasValidIdentity indicates if the AK has an associated certificate
// that includes a valid identity. Currently we only consider certificates
// that encode the TPM EK public key ID as one of its URI SANs, which is
// the default behavior of the Smallstep Attestation CA.
func (k *TPMKMS) hasValidIdentity(ak *tpm.AK, ekURL *url.URL) error {
	chain := ak.CertificateChain()
	if len(chain) == 0 {
		return ErrIdentityCertificateUnavailable
	}
	akCert := chain[0]

	now := time.Now()
	if now.Before(akCert.NotBefore) {
		return ErrIdentityCertificateNotYetValid
	}

	notAfter := akCert.NotAfter.Add(-1 * time.Minute).Truncate(time.Second)
	if now.After(notAfter) {
		return ErrIdentityCertificateExpired
	}

	// it's possible to disable early expiration errors for the AK identity
	// certificate when instantiating the TPMKMS.
	if k.identityEarlyRenewalEnabled {
		period := akCert.NotAfter.Sub(akCert.NotBefore).Truncate(time.Second)
		renewBefore := time.Duration(float64(period.Nanoseconds()) * (float64(k.identityRenewalPeriodPercentage) / 100))
		earlyAfter := akCert.NotAfter.Add(-1 * renewBefore)
		if now.After(earlyAfter) {
			return ErrIdentityCertificateIsExpiring
		}
	}

	// the Smallstep Attestation CA will issue AK certifiates that
	// contain the EK public key ID encoded as an URN by default.
	for _, u := range akCert.URIs {
		if ekURL.String() == u.String() {
			return nil
		}
	}

	// TODO(hs): we could consider checking other values to contain
	// a usable identity too.

	return ErrIdentityCertificateInvalid
}

// generateKeyID generates a key identifier from the
// SHA256 hash of the public key.
func generateKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("error marshaling public key: %w", err)
	}
	hash := sha256.Sum256(b)
	return hash[:], nil
}

// ekURL generates an EK URI containing the encoded key identifier
// for the EK.
func ekURL(keyID []byte) *url.URL {
	return &url.URL{
		Scheme: "urn",
		Opaque: "ek:sha256:" + base64.StdEncoding.EncodeToString(keyID),
	}
}

func parseTSS2(pemBytes []byte) (*tss2.TPMKey, error) {
	var block *pem.Block
	for len(pemBytes) > 0 {
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != "TSS2 PRIVATE KEY" {
			continue
		}

		key, err := tss2.ParsePrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed parsing TSS2 PEM: %w", err)
		}
		return key, nil
	}
	return nil, fmt.Errorf("failed parsing TSS2 PEM: block not found")
}

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func generateWindowsSubjectKeyID(pub crypto.PublicKey) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	var info subjectPublicKeyInfo
	if _, err = asn1.Unmarshal(b, &info); err != nil {
		return "", err
	}
	hash := sha1.Sum(info.SubjectPublicKey.Bytes) //nolint:gosec // required for Windows key ID calculation

	return hex.EncodeToString(hash[:]), nil
}

var _ apiv1.KeyManager = (*TPMKMS)(nil)
var _ apiv1.Attester = (*TPMKMS)(nil)
var _ apiv1.CertificateManager = (*TPMKMS)(nil)
var _ apiv1.CertificateChainManager = (*TPMKMS)(nil)
var _ apiv1.AttestationClient = (*attestationClient)(nil)
