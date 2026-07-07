//go:build !notpmkms

package tpmkms

import (
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
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/algorithm"
	"go.step.sm/crypto/tpm/attestation"
	"go.step.sm/crypto/tpm/storage"
	"go.step.sm/crypto/tpm/tss2"
	"go.step.sm/crypto/x509util"
)

func init() {
	apiv1.Register(apiv1.TPMKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// PreferredSignatureAlgorithms indicates the preferred selection of signature
// algorithms when an explicit value is omitted in CreateKeyRequest
var preferredSignatureAlgorithms []apiv1.SignatureAlgorithm

// SetPreferredSignatureAlgorithms sets the preferred signature algorithms
// to select from when explicit values are omitted in CreateKeyRequest
//
// # Experimental
//
// Notice: This method is EXPERIMENTAL and may be changed or removed in a later
// release.
func SetPreferredSignatureAlgorithms(algs []apiv1.SignatureAlgorithm) {
	preferredSignatureAlgorithms = algs
}

// PreferredSignatureAlgorithms returns the preferred signature algorithms
// to select from when explicit values are omitted in CreateKeyRequest
//
// # Experimental
//
// Notice: This method is EXPERIMENTAL and may be changed or removed in a later
// release.
func PreferredSignatureAlgorithms() []apiv1.SignatureAlgorithm {
	return preferredSignatureAlgorithms
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

type options struct {
	windowsCNG                       bool
	windowsCertificateStore          string
	windowsCertificateStoreLocation  string
	windowsIntermediateStore         string
	windowsIntermediateStoreLocation string
	attestationCABaseURL             string
	attestationCARootFile            string
	attestationCAInsecure            bool
	permanentIdentifier              string
	identityRenewalPeriodPercentage  int64
	identityEarlyRenewalEnabled      bool
}

// Option is the type used as a variadic argument in NewWithTPM.
//
// # Experimental
//
// Notice: This type is EXPERIMENTAL and may be changed or removed in a later
// release.
type Option func(o *options) error

// WithAttestationCA is the [Option] used to define the attestation CA.
func WithAttestationCA(caURL, rootFile string, insecure bool) Option {
	return func(o *options) error {
		o.attestationCABaseURL = caURL
		o.attestationCARootFile = rootFile
		o.attestationCAInsecure = insecure
		return nil
	}
}

// WithPermanentIdentifier is the [Option] used to define the permanent
// identifier.
func WithPermanentIdentifier(s string) Option {
	return func(o *options) error {
		o.permanentIdentifier = s
		return nil
	}
}

// WithDisableIdentityEarlyRenewal is the [Option] used to disable early
// renewal of the AK certificate.
func WithDisableIdentityEarlyRenewal() Option {
	return func(o *options) error {
		o.identityEarlyRenewalEnabled = false
		o.identityRenewalPeriodPercentage = 0
		return nil
	}
}

// WithIdentityEarlyRenewalPercentage is the [Option] used to change the
// lifetime percentage for renewing the AK certificate.
func WithIdentityEarlyRenewalPercentage(percentage int64) Option {
	return func(o *options) error {
		if percentage < 1 || percentage > 100 {
			return fmt.Errorf("renewal percentage must be between 1 and 100; got %d", percentage)
		}
		o.identityEarlyRenewalEnabled = true
		o.identityRenewalPeriodPercentage = percentage
		return nil
	}
}

// WithWindowsCertificateStore sets certificate store and location. It defaults
// to "My" and "user".
func WithWindowsCertificateStore(store, location string) Option {
	return func(o *options) error {
		if runtime.GOOS != "windows" {
			return fmt.Errorf(`certificate location is not supported on %s`, runtime.GOOS)
		}
		if store == "" {
			store = defaultStore
		}
		if location == "" {
			location = defaultStoreLocation
		}
		o.windowsCNG = true
		o.windowsCertificateStore = store
		o.windowsCertificateStoreLocation = location
		return nil
	}
}

// WithWindowsIntermediateStore sets intermediate certificate store and
// location. It defaults to "CA" and "user".
func WithWindowsIntermediateStore(store, location string) Option {
	return func(o *options) error {
		if runtime.GOOS != "windows" {
			return fmt.Errorf(`certificate location is not supported on %s`, runtime.GOOS)
		}
		if store == "" {
			store = defaultIntermediateStore
		}
		if location == "" {
			location = defaultIntermediateStoreLocation
		}
		o.windowsCNG = true
		o.windowsIntermediateStore = store
		o.windowsIntermediateStoreLocation = location
		return nil
	}
}

// ParseTPMOptions is a helper method that returns a slice of [tpm.NewTPMOption]
// for the given URI.
func ParseTPMOptions(u *uri.URI) []tpm.NewTPMOption {
	var opts []tpm.NewTPMOption
	if device := u.Get("device"); device != "" {
		opts = append(opts, tpm.WithDeviceName(device))
	}
	if storageDirectory := u.Get("storage-directory"); storageDirectory != "" {
		opts = append(opts, tpm.WithStore(storage.NewDirstore(storageDirectory, parseDirstoreOptions(u)...)))
	}
	return opts
}

// resolveStorageDirectory returns the TPM storage directory and dirstore
// options that [New] uses for the given options and parsed URI. The directory
// precedence is: a storage-directory in the URI wins, otherwise
// opts.StorageDirectory, otherwise the default "tpm". The dirstore options
// (e.g. the cache size) come from the URI via parseDirstoreOptions.
func resolveStorageDirectory(opts apiv1.Options, u *uri.URI) (string, []storage.DirstoreOption) {
	directory := "tpm" // store TPM objects in a relative tpm directory by default.
	if opts.StorageDirectory != "" {
		directory = opts.StorageDirectory
	}
	if u != nil {
		if d := u.Get("storage-directory"); d != "" {
			directory = d
		}
	}
	return directory, parseDirstoreOptions(u)
}

// parseDirstoreOptions returns the [storage.DirstoreOption]s encoded in the
// URI. It currently supports storage-cache-size, the maximum size in bytes of
// the dirstore's in-memory read cache; setting it to 0 (or any negative value)
// disables caching so every read reflects the current on-disk state.
func parseDirstoreOptions(u *uri.URI) []storage.DirstoreOption {
	if u == nil {
		return nil
	}
	var opts []storage.DirstoreOption
	if size := u.GetInt("storage-cache-size"); size != nil {
		// A negative size is meaningless for a cache budget; treat it as 0
		// (disabled) rather than silently keeping the default — less surprising
		// than ignoring it.
		cacheSize := uint64(0)
		if *size > 0 {
			cacheSize = uint64(*size)
		}
		opts = append(opts, storage.WithCacheSize(cacheSize))
	}
	return opts
}

// ParseOptions is a helper method that returns a slice of [Option] for
// the give URI.
func ParseOptions(u *uri.URI) []Option {
	opts := []Option{
		WithAttestationCA(u.Get("attestation-ca-url"), u.Get("attestation-ca-root"), u.GetBool("attestation-ca-insecure")),
		WithPermanentIdentifier(u.Get("permanent-identifier")), // TODO(hs): determine if this is needed
	}

	if u.GetBool("disable-early-renewal") {
		opts = append(opts, WithDisableIdentityEarlyRenewal())
	} else if percentage := u.GetInt("renewal-percentage"); percentage != nil {
		opts = append(opts, WithIdentityEarlyRenewalPercentage(*percentage))
	}

	// Microsoft Cryptography API: Next Generation (CNG) options
	// TODO(hs): maybe change the option flag or make this the default on Windows
	if u.GetBool("enable-cng") {
		opts = append(opts,
			WithWindowsCertificateStore(u.Get("store"), u.Get("store-location")),
			WithWindowsIntermediateStore(u.Get("intermediate-store"), u.Get("intermediate-store-location")),
		)
	}

	return opts
}

// TPMKMS is a KMS implementation backed by a TPM.
type TPMKMS struct {
	tpm                       *tpm.TPM
	windowsCertificateManager capiCertificateManager
	opts                      *options

	// searchKeysFn, when set, replaces [TPMKMS.SearchKeys] for internal
	// callers. It exists so the key-enumeration dependent code paths (such as
	// CleanupCredentials) can be exercised in tests without a live TPM. It
	// defaults to [TPMKMS.SearchKeys] via [TPMKMS.searchKeys].
	searchKeysFn func(*apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error)
}

// searchKeys runs a key search through the testable seam, falling back to the
// real [TPMKMS.SearchKeys] implementation when no override is configured.
func (k *TPMKMS) searchKeys(req *apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error) {
	if k.searchKeysFn != nil {
		return k.searchKeysFn(req)
	}
	return k.SearchKeys(req)
}

type algorithmAttributes struct {
	Type     string
	Curve    int
	Requires []algorithm.Algorithm
}

var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]algorithmAttributes{
	apiv1.UnspecifiedSignAlgorithm: {"RSA", -1, []algorithm.Algorithm{algorithm.AlgorithmRSA}},
	apiv1.SHA256WithRSA:            {"RSA", -1, []algorithm.Algorithm{algorithm.AlgorithmRSA, algorithm.AlgorithmSHA256}},
	apiv1.SHA384WithRSA:            {"RSA", -1, []algorithm.Algorithm{algorithm.AlgorithmRSA, algorithm.AlgorithmSHA384}},
	apiv1.SHA512WithRSA:            {"RSA", -1, []algorithm.Algorithm{algorithm.AlgorithmRSA, algorithm.AlgorithmSHA512}},
	apiv1.SHA256WithRSAPSS:         {"RSA", -1, []algorithm.Algorithm{algorithm.AlgorithmRSAPSS, algorithm.AlgorithmSHA256}},
	apiv1.SHA384WithRSAPSS:         {"RSA", -1, []algorithm.Algorithm{algorithm.AlgorithmRSAPSS, algorithm.AlgorithmSHA384}},
	apiv1.SHA512WithRSAPSS:         {"RSA", -1, []algorithm.Algorithm{algorithm.AlgorithmRSAPSS, algorithm.AlgorithmSHA512}},
	apiv1.ECDSAWithSHA256:          {"ECDSA", 256, []algorithm.Algorithm{algorithm.AlgorithmECDSA, algorithm.AlgorithmSHA256}},
	apiv1.ECDSAWithSHA384:          {"ECDSA", 384, []algorithm.Algorithm{algorithm.AlgorithmECDSA, algorithm.AlgorithmSHA384}},
	apiv1.ECDSAWithSHA512:          {"ECDSA", 521, []algorithm.Algorithm{algorithm.AlgorithmECDSA, algorithm.AlgorithmSHA512}},
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
	var uriOptions []Option
	var u *uri.URI

	// Parse the URI up front so the default store below can honor any storage
	// options it carries (e.g. storage-cache-size).
	if opts.URI != "" {
		if u, err = uri.ParseWithScheme(Scheme, opts.URI); err != nil {
			return nil, fmt.Errorf("failed parsing %q as URI: %w", opts.URI, err)
		}
		uriOptions = ParseOptions(u)
	}

	storageDirectory, dirstoreOptions := resolveStorageDirectory(opts, u)
	tpmOpts := []tpm.NewTPMOption{
		tpm.WithStore(storage.NewDirstore(storageDirectory, dirstoreOptions...)),
	}
	if u != nil {
		if device := u.Get("device"); device != "" {
			tpmOpts = append(tpmOpts, tpm.WithDeviceName(device))
		}
	}

	t, err := tpm.New(tpmOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed creating new TPM: %w", err)
	}

	return NewWithTPM(ctx, t, uriOptions...)
}

// NewWithTPM initializes a new KMS backed by the given TPM.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func NewWithTPM(ctx context.Context, t *tpm.TPM, opts ...Option) (*TPMKMS, error) {
	o := &options{
		identityEarlyRenewalEnabled:      true,
		identityRenewalPeriodPercentage:  60, // default to AK certificate renewal at 60% of lifetime
		windowsCNG:                       false,
		windowsCertificateStore:          defaultStore,
		windowsCertificateStoreLocation:  defaultStoreLocation,
		windowsIntermediateStore:         defaultIntermediateStore,
		windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
	}
	for _, fn := range opts {
		if err := fn(o); err != nil {
			return nil, err
		}
	}

	var cm capiCertificateManager

	// TODO(hs): support a mode in which the TPM storage doesn't rely on JSON on Windows
	// at all, but directly feeds into OS native storage? Some operations can be NOOPs, such
	// as the ones that create AKs and keys. Is all of the data available in the keys stored
	// with Windows, incl. the attestation certification?
	if o.windowsCNG {
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

		cm, ok = km.(capiCertificateManager)
		if !ok {
			return nil, fmt.Errorf("unexpected type %T; expected capiCertificateManager", km)
		}
	}

	return &TPMKMS{
		tpm:                       t,
		windowsCertificateManager: cm,
		opts:                      o,
	}, nil
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

	ctx := context.Background()
	caps, err := k.tpm.GetCapabilities(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not get TPM capabilities: %w", err)
	}

	var (
		v  algorithmAttributes
		ok bool
	)
	if !properties.ak && req.SignatureAlgorithm == apiv1.UnspecifiedSignAlgorithm && len(preferredSignatureAlgorithms) > 0 {
		for _, alg := range preferredSignatureAlgorithms {
			v, ok = signatureAlgorithmMapping[alg]
			if !ok {
				return nil, fmt.Errorf("TPMKMS does not support signature algorithm %q", alg)
			}

			if caps.SupportsAlgorithms(v.Requires) {
				break
			}
		}
	} else {
		v, ok = signatureAlgorithmMapping[req.SignatureAlgorithm]
		if !ok {
			return nil, fmt.Errorf("TPMKMS does not support signature algorithm %q", req.SignatureAlgorithm)
		}

		if !caps.SupportsAlgorithms(v.Requires) {
			return nil, fmt.Errorf("signature algorithm %q not supported by the TPM device", req.SignatureAlgorithm)
		}
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

	machineKey := properties.isMachineKey()

	var privateKey any
	if properties.ak {
		// NOTE: size is never passed for AKs; it's hardcoded to 2048 in lower
		// levels. The AK must honor the requested key-scope: an attested key
		// inherits its AK's scope (AttestKey enforces this symmetrically), so
		// a machine-scoped attested key requires a machine-scoped AK. Creating
		// the AK with the plain (user-default) CreateAK here would make every
		// machine-scoped attestation fail with a scope mismatch.
		ak, err := k.tpm.CreateAKWithConfig(ctx, properties.name, tpm.CreateAKConfig{MachineKey: machineKey})
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

		// Preserve key-scope in the returned URI so re-opens use the matching
		// scope (mirrors the non-AK path below).
		createdAKURI := fmt.Sprintf("tpmkms:name=%s;ak=true", ak.Name())
		if machineKey {
			createdAKURI = fmt.Sprintf("%s;key-scope=machine", createdAKURI)
		}
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
			MachineKey:     machineKey,
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
			Algorithm:  v.Type,
			Size:       size,
			MachineKey: machineKey,
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

	// Preserve key-scope in the returned URI so subsequent CreateSigner /
	// DeleteKey calls land in the right scope. The bug we hit before was
	// exactly this: the returned URI had only "name=", so re-opens
	// defaulted to user scope and failed to find machine-stored keys.
	createdKeyURI := fmt.Sprintf("tpmkms:name=%s", key.Name())
	if properties.attestBy != "" {
		createdKeyURI = fmt.Sprintf("%s;attest-by=%s", createdKeyURI, key.AttestedBy())
	}
	if machineKey {
		createdKeyURI = fmt.Sprintf("%s;key-scope=machine", createdKeyURI)
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

// DeleteKey deletes a key identified by name from the TPMKMS.
//
// # Experimental
//
// Notice: This method is EXPERIMENTAL and may be changed or removed in a later
// release.
func (k *TPMKMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("deleteKeyRequest 'name' cannot be empty")
	}
	properties, err := parseNameURI(req.Name)
	if err != nil {
		return fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	ctx := context.Background()
	if properties.ak {
		if err := k.tpm.DeleteAK(ctx, properties.name); err != nil {
			return notFoundError(err)
		}
	} else {
		if err := k.tpm.DeleteKey(ctx, properties.name); err != nil {
			return notFoundError(err)
		}
	}

	return nil
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
			key, err := k.getKey(ctx, properties.name)
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
			ak, err := k.getAK(ctx, properties.name)
			if err != nil {
				return nil, err
			}
			akPub := ak.Public()
			if akPub == nil {
				return nil, errors.New("failed getting AK public key")
			}
			return akPub, nil
		}

		key, err := k.getKey(ctx, properties.name)
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
		ak, err := k.getAK(ctx, properties.name)
		if err != nil {
			return nil, err
		}
		chain = ak.CertificateChain()
	} else {
		key, err := k.getKey(ctx, properties.name)
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

	location := k.opts.windowsCertificateStoreLocation
	if o.storeLocation != "" {
		location = o.storeLocation
	}
	store := k.opts.windowsCertificateStore
	if o.store != "" {
		store = o.store
	}
	intermediateCAStoreLocation := k.opts.windowsIntermediateStoreLocation
	if o.intermediateStoreLocation != "" {
		intermediateCAStoreLocation = o.intermediateStoreLocation
	}
	intermediateCAStore := k.opts.windowsIntermediateStore
	if o.intermediateStore != "" {
		intermediateCAStore = o.intermediateStore
	}

	subjectKeyID, err := generateWindowsSubjectKeyID(pub)
	if err != nil {
		return nil, fmt.Errorf("failed generating subject key id: %w", err)
	}

	return k.windowsCertificateManager.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
		Name: uri.New("capi", url.Values{
			"key-id":                      []string{subjectKeyID},
			"store-location":              []string{location},
			"store":                       []string{store},
			"intermediate-store-location": []string{intermediateCAStoreLocation},
			"intermediate-store":          []string{intermediateCAStore},
			"issuer":                      []string{o.issuer},
			"friendly-name":               []string{o.friendlyName},
			"description":                 []string{o.description},
		}).String(),
	})
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
		ak, err := k.getAK(ctx, properties.name)
		if err != nil {
			return err
		}
		err = ak.SetCertificateChain(ctx, req.CertificateChain)
		if err != nil {
			return fmt.Errorf("failed storing certificate for AK %q: %w", properties.name, err)
		}
	} else {
		key, err := k.getKey(ctx, properties.name)
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

	location := k.opts.windowsCertificateStoreLocation
	if o.storeLocation != "" {
		location = o.storeLocation
	}
	store := k.opts.windowsCertificateStore
	if o.store != "" {
		store = o.store
	}

	skipFindCertificateKey := "false"
	if o.skipFindCertificateKey {
		skipFindCertificateKey = "true"
	}
	intermediateCAStoreLocation := k.opts.windowsIntermediateStoreLocation
	if o.intermediateStoreLocation != "" {
		intermediateCAStoreLocation = o.intermediateStoreLocation
	}
	intermediateCAStore := k.opts.windowsIntermediateStore
	if o.intermediateStore != "" {
		intermediateCAStore = o.intermediateStore
	}

	// Associate the stored certificate with the TPM key explicitly. The agent
	// stores certificates with skip-find-certificate-key set (to avoid a smart
	// card prompt during discovery), and CryptFindCertificateKeyProvInfo cannot
	// discover machine-scoped Platform Crypto Provider keys anyway, so we hand
	// the CAPI layer the exact key: its CNG container name, the TPM provider,
	// and its key scope (machine vs user). The container name is the key name
	// prefixed with "app-" (see prefixKey / go-attestation), which is how the
	// key was persisted in the PCP KSP. CAPI resolves the keyset from key-scope,
	// falling back to store-location when key-scope is unset.
	v := url.Values{
		"store-location":              []string{location},
		"store":                       []string{store},
		"friendly-name":               []string{o.friendlyName},
		"description":                 []string{o.description},
		"skip-find-certificate-key":   []string{skipFindCertificateKey},
		"intermediate-store-location": []string{intermediateCAStoreLocation},
		"intermediate-store":          []string{intermediateCAStore},
	}
	if o.name != "" {
		v.Set("key", tpm.ApplicationKeyName(o.name))
		v.Set("provider", microsoftPCP)
		if o.keyScope != "" {
			v.Set("key-scope", o.keyScope)
		}
	}

	return k.windowsCertificateManager.StoreCertificateChain(&apiv1.StoreCertificateChainRequest{
		Name:             uri.New("capi", v).String(),
		CertificateChain: req.CertificateChain,
	})
}

// CleanupCredentials implements [apiv1.CredentialsCleaner]. On Windows it finds
// all certificates in the configured certificate store issued by the "issuer"
// in req.Name (optionally restricted to req.RawSubject) and deletes any that
// have already expired. The "store-location" and "store" fields of req.Name
// override the store configured on the TPMKMS instance.
//
// When req.Name carries "delete-key=true", the private key paired with each
// expired certificate is removed as well: it first attempts a full teardown
// through [TPMKMS.DeleteKey], which removes both the TPM storage entry and the
// CNG/NCrypt key container. When DeleteKey cannot act on the key at all — the
// TPM storage can't be loaded, the key isn't present in storage, or the TPM
// can't be opened — it falls back to deleting the CNG key container directly
// while removing the certificate. Without "delete-key=true" only the expired
// certificates are removed and their keys are left in place.
func (k *TPMKMS) CleanupCredentials(req *apiv1.CleanupCredentialsRequest) error {
	if req == nil {
		return errors.New("cleanupCredentialsRequest cannot be nil")
	}

	if !k.usesWindowsCertificateStore() {
		// CleanupCredentials is only supported when the TPMKMS is configured to
		// use the Windows certificate store. Signal that explicitly instead of
		// silently succeeding, consistent with how the platform KMS reports
		// unsupported operations.
		return apiv1.NotImplementedError{}
	}

	o, err := parseNameURI(req.Name)
	if err != nil {
		return fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}
	if o.issuer == "" {
		return errors.New(`"issuer" is required`)
	}

	location := k.opts.windowsCertificateStoreLocation
	if o.storeLocation != "" {
		location = o.storeLocation
	}
	store := k.opts.windowsCertificateStore
	if o.store != "" {
		store = o.store
	}

	loadURI := uri.New("capi", url.Values{
		"store-location": []string{location},
		"store":          []string{store},
		"issuer":         []string{o.issuer},
	}).String()
	certs, err := k.windowsCertificateManager.FindCertificatesByIssuer(&apiv1.LoadCertificateRequest{Name: loadURI}, req.RawSubject)
	if err != nil {
		return fmt.Errorf("failed loading certificates by issuer %q: %w", o.issuer, err)
	}

	var deleteErrors []error

	// Map every managed key's Subject Key Identifier to its TPMKMS URI so an
	// expired certificate can be traced back to the key that needs deleting.
	// Only required when the request asks for the keys to be deleted.
	var keysBySKI map[string]string
	if o.deleteKey {
		// keyNamesBySubjectKeyID is best-effort: it returns whatever keys it
		// could load (possibly none) plus an error for the ones it couldn't.
		// Don't abort on that error — certificates whose key is missing from
		// the map fall through to the direct CNG deletion path below — but do
		// record it so the failure is surfaced rather than swallowed.
		keysBySKI, err = k.keyNamesBySubjectKeyID()
		if err != nil {
			deleteErrors = append(deleteErrors, fmt.Errorf("failed enumerating some keys; affected certificates fall back to direct key deletion: %w", err))
		}
	}

	now := time.Now()
	for _, cert := range certs {
		if !cert.NotAfter.Before(now) {
			continue
		}

		// deleteKey indicates whether the CNG key container should be removed
		// together with the certificate. It's only ever true when the request
		// asked for it, and then only when the key can't be torn down through
		// the regular DeleteKey path.
		deleteKey := false
		if o.deleteKey {
			result, err := k.deleteKeyForCertificate(cert, keysBySKI)
			if err != nil {
				deleteErrors = append(deleteErrors, err)
			}
			deleteKey = result
		}

		if err := k.deleteCertificateBySerial(location, store, o.issuer, cert.SerialNumber, deleteKey); err != nil {
			deleteErrors = append(deleteErrors, fmt.Errorf("failed deleting expired certificate (serial %s): %w", cert.SerialNumber.Text(16), err))
		}
	}

	return errors.Join(deleteErrors...)
}

// deleteKeyForCertificate tears down the key paired with cert. It returns
// whether the caller must still remove the CNG key container directly when
// deleting the certificate (fallback path), and any error encountered.
//
// When cert maps to a managed key it tries a full teardown via
// [TPMKMS.DeleteKey]; on success the container is already gone (returns false),
// and only when DeleteKey couldn't touch the container at all does it ask for a
// direct deletion (returns true). When cert maps to no managed key — an orphan
// certificate — it also asks for a direct deletion.
func (k *TPMKMS) deleteKeyForCertificate(cert *x509.Certificate, keysBySKI map[string]string) (bool, error) {
	ski, err := x509util.GenerateSubjectKeyID(cert.PublicKey)
	if err != nil {
		return false, fmt.Errorf("failed generating key identifier for expired certificate (serial %s): %w", cert.SerialNumber.Text(16), err)
	}

	name, ok := keysBySKI[hex.EncodeToString(ski)]
	if !ok {
		// Orphan certificate: no managed key maps to it, so the container (if
		// any) must be deleted directly.
		return true, nil
	}

	switch err := k.DeleteKey(&apiv1.DeleteKeyRequest{Name: name}); {
	case err == nil:
		// DeleteKey removed both the TPM storage entry and the CNG key
		// container, so only the certificate itself is left to delete.
		return false, nil
	case shouldFallbackToDirectKeyDelete(err):
		// DeleteKey never reached the key container; delete it directly
		// alongside the certificate.
		return true, nil
	default:
		// DeleteKey acted but failed in some other way; surface the error, but
		// still remove the certificate without re-deleting the key.
		return false, fmt.Errorf("failed deleting key for expired certificate (serial %s): %w", cert.SerialNumber.Text(16), err)
	}
}

// keyNamesBySubjectKeyID returns a map from the hex-encoded Subject Key
// Identifier of every non-AK key managed by the TPMKMS to its TPMKMS URI. It is
// used to trace a certificate back to the key that produced it.
//
// The key search is best-effort: it may fail to load some keys and still return
// the ones it could. The map is built from whatever keys were returned, and any
// load failures are joined into the returned error so the caller can record
// them. Certificates whose key could not be loaded simply won't appear in the
// map and are handled by the caller's orphan/direct-delete path. A hard failure
// that yields no response at all is returned as-is.
func (k *TPMKMS) keyNamesBySubjectKeyID() (map[string]string, error) {
	resp, err := k.searchKeys(&apiv1.SearchKeysRequest{
		Query: uri.New(Scheme, url.Values{"ak": []string{"false"}}).String(),
	})
	if resp == nil {
		return nil, err
	}

	var errs []error
	if err != nil {
		errs = append(errs, err)
	}

	keysBySKI := make(map[string]string, len(resp.Results))
	for _, result := range resp.Results {
		ski, err := x509util.GenerateSubjectKeyID(result.PublicKey)
		if err != nil {
			// Don't drop the rest of the map over one bad public key; record
			// it and carry on, the same way SearchKeys treats unloadable keys.
			errs = append(errs, fmt.Errorf("failed generating subject key id for %q: %w", result.Name, err))
			continue
		}
		keysBySKI[hex.EncodeToString(ski)] = result.Name
	}

	return keysBySKI, errors.Join(errs...)
}

// deleteCertificateBySerial removes the certificate identified by issuer and
// serial from the configured Windows certificate store, backed by the CAPIKMS
// instance. When deleteKey is true the paired CNG key container is removed too.
func (k *TPMKMS) deleteCertificateBySerial(location, store, issuer string, serial *big.Int, deleteKey bool) error {
	uv := url.Values{}
	uv.Set("store-location", location)
	uv.Set("store", store)
	uv.Set("issuer", issuer)
	uv.Set("serial", "0x"+serial.Text(16))
	if deleteKey {
		uv.Set("delete-key", "true")
	}

	return k.windowsCertificateManager.DeleteCertificate(&apiv1.DeleteCertificateRequest{
		Name: uri.New("capi", uv).String(),
	})
}

// shouldFallbackToDirectKeyDelete reports whether a [TPMKMS.DeleteKey] error
// means the CNG key container was never touched — the TPM storage couldn't be
// loaded, the key wasn't present in storage, or the TPM couldn't be opened — so
// the caller must fall back to deleting the key container directly.
func shouldFallbackToDirectKeyDelete(err error) bool {
	if errors.Is(err, apiv1.NotFoundError{}) || errors.Is(err, tpm.ErrNotFound) {
		return true
	}

	msg := err.Error()
	return strings.Contains(msg, "failed loading from TPM storage") ||
		strings.Contains(msg, "failed opening TPM")
}

// DeleteCertificate deletes a certificate for the key identified by name from the
// TPMKMS. If the instance is configured to use the Windows certificate store, it'll
// delete the certificate from the certificate store, backed by a CAPIKMS instance.
//
// It's possible to delete a specific certificate for a key by specifying it's SHA1
// or serial. This is only supported if the instance is configured to use the Windows
// certificate store.
//
// By default only the certificate is removed; the paired CNG private key is left
// in place, since a key may legitimately outlive a certificate (e.g. reused
// across renewals). Set "delete-key=true" on the request URI to remove the key
// along with the certificate.
//
// # Experimental
//
// Notice: This method is EXPERIMENTAL and may be changed or removed in a later
// release.
func (k *TPMKMS) DeleteCertificate(req *apiv1.DeleteCertificateRequest) error {
	if req.Name == "" {
		return errors.New("deleteCertificateRequest 'name' cannot be empty")
	}

	if k.usesWindowsCertificateStore() {
		if err := k.deleteCertificateFromWindowsCertificateStore(&apiv1.DeleteCertificateRequest{
			Name: req.Name,
		}); err != nil {
			return fmt.Errorf("failed deleting certificate from Windows platform cryptography provider: %w", err)
		}

		return nil
	}

	// TODO(hs): support delete by serial? If not, the behavior for TPM storage and Windows
	// certificate store storage will be different, and may need different behavior when
	// implementing certificate management.

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	ctx := context.Background()
	if properties.ak {
		ak, err := k.getAK(ctx, properties.name)
		if err != nil {
			return err
		}
		if err := ak.SetCertificateChain(ctx, nil); err != nil {
			return fmt.Errorf("failed storing certificate for AK %q: %w", properties.name, err)
		}
	} else {
		key, err := k.getKey(ctx, properties.name)
		if err != nil {
			return err
		}
		if err := key.SetCertificateChain(ctx, nil); err != nil {
			return fmt.Errorf("failed storing certificate for key %q: %w", properties.name, err)
		}
	}

	return nil
}

func (k *TPMKMS) deleteCertificateFromWindowsCertificateStore(req *apiv1.DeleteCertificateRequest) error {
	o, err := parseNameURI(req.Name)
	if err != nil {
		return fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	location := k.opts.windowsCertificateStoreLocation
	if o.storeLocation != "" {
		location = o.storeLocation
	}
	store := k.opts.windowsCertificateStore
	if o.store != "" {
		store = o.store
	}

	uv := url.Values{}
	uv.Set("store-location", location)
	uv.Set("store", store)
	// Only remove the CNG private key paired with the certificate when the
	// caller explicitly asked for it via "delete-key=true". Deleting the key by
	// default would be surprising: a key may legitimately outlive a certificate
	// (e.g. reused across renewals), and the non-Windows certificate store path
	// keeps the key on disk regardless.
	if o.deleteKey {
		uv.Set("delete-key", "true")
	}

	switch {
	case o.serial != "":
		uv.Set("serial", o.serial)
		uv.Set("issuer", o.issuer)
	case o.keyID != "":
		uv.Set("key-id", o.keyID)
	case o.sha1 != "":
		uv.Set("sha1", o.sha1)
	case o.name != "":
		keyID, err := k.getSubjectKeyID(req.Name)
		if err != nil {
			return fmt.Errorf("error getting key-id: %w", err)
		}
		uv.Set("key-id", hex.EncodeToString(keyID))
	default:
		return errors.New(`at least one of "serial", "key-id", "sha1" or "name" is expected to be set`)
	}

	if err := k.windowsCertificateManager.DeleteCertificate(&apiv1.DeleteCertificateRequest{
		Name: uri.New("capi", uv).String(),
	}); err != nil {
		return fmt.Errorf("failed deleting certificate using Windows platform cryptography provider: %w", err)
	}

	return nil
}

func (k *TPMKMS) getSubjectKeyID(name string) ([]byte, error) {
	key, err := k.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: name,
	})
	if err != nil {
		return nil, err
	}
	return x509util.GenerateSubjectKeyID(key)
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
	if k.opts.attestationCABaseURL == "" {
		return nil, errors.New("failed creating attestation client: attestation CA base URL must not be empty")
	}
	// prepare a client to perform attestation with an Attestation CA
	attestationClientOptions := []attestation.Option{attestation.WithRootsFile(k.opts.attestationCARootFile)}
	if k.opts.attestationCAInsecure {
		attestationClientOptions = append(attestationClientOptions, attestation.WithInsecure())
	}
	client, err := attestation.NewClient(k.opts.attestationCABaseURL, attestationClientOptions...)
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
	if k.opts.permanentIdentifier != "" && permanentIdentifier != k.opts.permanentIdentifier {
		return nil, fmt.Errorf("the provided permanent identifier %q does not match the EK URL %q", k.opts.permanentIdentifier, permanentIdentifier)
	}

	var key *tpm.Key
	akName := properties.name
	if !properties.ak {
		key, err = k.getKey(ctx, properties.name)
		if err != nil {
			return nil, err
		}
		if !key.WasAttested() {
			return nil, fmt.Errorf("key %q was not attested", key.Name())
		}
		akName = key.AttestedBy()
	}

	ak, err := k.getAK(ctx, akName)
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

// SearchKeys searches for keys according to the query URI in the request. By
// default, with the query "tpmkms:", it will return all application and
// attestation keys managed by the KMS. The supported queries are:
//
//   - "tpmkms:" will return all application keys and AKs managed by the KMS
//   - "tpmkms:ak=true" will return all AKs managed by the KMS
//   - "tpmkms:ak=false" will return all the application keys managed by the KMS
//   - "tpmkms:name=my-name" will only return the application key and AK with the selected name
//   - "tpmkms:name=my-name;ak=true" will only return the AK with the selected name
//   - "tpmkms:name=my-name;ak=false" will only return the application key with the selected name
//
// SearchKeys is best-effort. Enumerating the keys (ListKeys/ListAKs) or loading
// an individual key's signer can fail when the TPM can't be opened, its backing
// storage can't be read, or a key's material is corrupt or no longer present —
// for example a Windows PCP/CNG keyset reporting NTE_BAD_KEYSET, or a CNG key
// container removed out of band. Rather than failing the whole search over one
// bad key, it returns the keys it could load together with a joined error
// describing the ones it could not. Callers that need every key should treat a
// non-nil error as fatal; callers that can work with a subset (e.g. credential
// cleanup) can use the returned results regardless.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (k *TPMKMS) SearchKeys(req *apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error) {
	if req.Query == "" {
		return nil, fmt.Errorf("searchKeysRequest 'query' cannot be empty")
	}

	u, err := uri.ParseWithScheme(Scheme, req.Query)
	if err != nil {
		return nil, fmt.Errorf("searchKeysRequest failed: %w", err)
	}

	var (
		name        = u.Get("name")
		ak          = u.GetBool("ak")
		hasAK       = u.Has("ak")
		includeAKs  = !hasAK || ak
		includeKeys = !hasAK || !ak
		aks         []searchableAK
		keys        []searchableKey
		errs        []error
	)

	// List AKs. A failure to enumerate the AKs is collected as a partial error
	// rather than aborting: the application keys may still be searchable, and
	// callers can decide whether the missing AKs matter.
	if includeAKs {
		listed, err := k.tpm.ListAKs(context.Background())
		if err != nil {
			errs = append(errs, fmt.Errorf("failed listing attestation keys: %w", err))
		} else {
			aks = make([]searchableAK, len(listed))
			for i := range listed {
				aks[i] = listed[i]
			}
		}
	}

	// List Keys, same best-effort handling as the AKs above.
	if includeKeys {
		listed, err := k.tpm.ListKeys(context.Background())
		if err != nil {
			errs = append(errs, fmt.Errorf("failed listing keys: %w", err))
		} else {
			keys = make([]searchableKey, len(listed))
			for i := range listed {
				keys[i] = listed[i]
			}
		}
	}

	results, buildErrs := buildSearchKeysResults(aks, keys, name)
	errs = append(errs, buildErrs...)

	// Best-effort contract: the successfully loaded keys are always returned in
	// resp, alongside a joined error describing any keys (or key lists) that
	// could not be loaded. Callers that require completeness can treat a
	// non-nil error as fatal; callers that can make progress with a subset
	// (such as CleanupCredentials) keep using resp regardless. errors.Join
	// returns nil when errs is empty.
	return &apiv1.SearchKeysResponse{Results: results}, errors.Join(errs...)
}

// searchableAK and searchableKey are the minimal views of [tpm.AK] and
// [tpm.Key] needed to build search results. They exist so the best-effort
// result-building logic can be unit tested with fakes that, for example, fail
// to produce a signer.
type searchableAK interface {
	Name() string
	Public() crypto.PublicKey
}

type searchableKey interface {
	Name() string
	AttestedBy() string
	Signer(context.Context) (crypto.Signer, error)
}

// buildSearchKeysResults converts the listed AKs and keys into search results,
// filtering by name when set. AKs always yield a result. A key whose signer
// cannot be loaded (e.g. a corrupt keyset) does not abort the whole search:
// instead the failure is recorded and the remaining keys are still returned.
// The returned error slice is empty when everything loaded.
func buildSearchKeysResults(aks []searchableAK, keys []searchableKey, name string) ([]apiv1.SearchKeyResult, []error) {
	var (
		results []apiv1.SearchKeyResult
		errs    []error
	)

	for _, ak := range aks {
		if name != "" && name != ak.Name() {
			continue
		}
		results = append(results, apiv1.SearchKeyResult{
			Name: uri.New(Scheme, url.Values{
				"name": []string{ak.Name()},
				"ak":   []string{"true"},
			}).String(),
			PublicKey: ak.Public(),
		})
	}

	for _, key := range keys {
		if name != "" && name != key.Name() {
			continue
		}

		values := url.Values{"name": []string{key.Name()}}
		if attestedBy := key.AttestedBy(); attestedBy != "" {
			values.Set("attest-by", attestedBy)
		}
		keyURI := uri.New(Scheme, values).String()

		signer, err := key.Signer(context.Background())
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to create a signer for %q: %w", keyURI, err))
			continue
		}

		results = append(results, apiv1.SearchKeyResult{
			Name:      keyURI,
			PublicKey: signer.Public(),
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: keyURI,
			},
		})
	}

	return results, errs
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
	if k.opts.identityEarlyRenewalEnabled {
		period := akCert.NotAfter.Sub(akCert.NotBefore).Truncate(time.Second)
		renewBefore := time.Duration(float64(period.Nanoseconds()) * (float64(k.opts.identityRenewalPeriodPercentage) / 100))
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

func (k *TPMKMS) getAK(ctx context.Context, name string) (*tpm.AK, error) {
	ak, err := k.tpm.GetAK(ctx, name)
	if err != nil {
		return nil, notFoundError(err)
	}
	return ak, nil
}

func (k *TPMKMS) getKey(ctx context.Context, name string) (*tpm.Key, error) {
	key, err := k.tpm.GetKey(ctx, name)
	if err != nil {
		return nil, notFoundError(err)
	}
	return key, nil
}

func notFoundError(err error) error {
	if errors.Is(err, tpm.ErrNotFound) {
		return apiv1.NotFoundError{
			Message: err.Error(),
		}
	}
	return err
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

type capiCertificateManager interface {
	apiv1.CertificateChainManager
	apiv1.CertificateDeleter
	apiv1.CredentialsCleaner
	FindCertificatesByIssuer(req *apiv1.LoadCertificateRequest, rawSubject []byte) ([]*x509.Certificate, error)
}

var (
	_ apiv1.KeyManager              = (*TPMKMS)(nil)
	_ apiv1.Attester                = (*TPMKMS)(nil)
	_ apiv1.CertificateManager      = (*TPMKMS)(nil)
	_ apiv1.CertificateChainManager = (*TPMKMS)(nil)
	_ apiv1.CredentialsCleaner      = (*TPMKMS)(nil)
	_ apiv1.CertificateDeleter      = (*TPMKMS)(nil)
	_ apiv1.AttestationClient       = (*attestationClient)(nil)
)
