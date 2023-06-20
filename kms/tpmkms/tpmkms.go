//go:build !notpmkms
// +build !notpmkms

package tpmkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"

	"go.step.sm/crypto/internal/step"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/attestation"
	"go.step.sm/crypto/tpm/storage"
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
	tpm                   *tpm.TPM
	attestationCABaseURL  string
	attestationCARootFile string
	attestationCAInsecure bool
	permanentIdentifier   string
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
// an instance of TPMKMS is created, is $STEPPATH/tpm.
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
// Attestation support in the TPMKMS is considered EXPERIMENTAL. It
// is expected that there will be changes to the configuration that
// be provided and the attestation flow.
//
// The TPMKMS implementation is backed by an instance of the TPM from
// the `tpm` package. If the TPMKMS operations aren't sufficient for
// your use case, use a tpm.TPM instance instead.
func New(ctx context.Context, opts apiv1.Options) (kms *TPMKMS, err error) {
	kms = &TPMKMS{}
	storageDirectory := filepath.Join(step.Path(), "tpm") // store TPM objects in $STEPPATH/tpm by default
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
	}

	kms.tpm, err = tpm.New(tpmOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed creating new TPM: %w", err)
	}

	return
}

// CreateKey generates a new key in the TPM KMS and returns the public key.
//
// The `name` in the [apiv1.CreateKeyRequest] can be used to specify
// some key properties. These are as follows:
//
//   - name=<name>: specify the name to identify the key with
//   - ak=true: if set to true, an Attestation Key (AK) will be created instead of an application key
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
	if properties.ak {
		ak, err := k.tpm.CreateAK(ctx, properties.name) // NOTE: size is never passed for AKs; it's hardcoded to 2048 in lower levels.
		if err != nil {
			if errors.Is(err, tpm.ErrExists) {
				return nil, apiv1.AlreadyExistsError{Message: err.Error()}
			}
			return nil, fmt.Errorf("failed creating AK: %w", err)
		}
		createdAKURI := fmt.Sprintf("tpmkms:name=%s;ak=true", ak.Name())
		return &apiv1.CreateKeyResponse{
			Name:      createdAKURI,
			PublicKey: ak.Public(),
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

	signer, err := key.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting signer for key: %w", err)
	}

	createdKeyURI := fmt.Sprintf("tpmkms:name=%s", key.Name())
	if properties.attestBy != "" {
		createdKeyURI = fmt.Sprintf("%s;attest-by=%s", createdKeyURI, key.AttestedBy())
	}

	return &apiv1.CreateKeyResponse{
		Name:      createdKeyURI,
		PublicKey: signer.Public(),
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: createdKeyURI,
			Signer:     signer,
		},
	}, nil
}

// CreateSigner creates a signer using a key present in the TPM KMS.
func (k *TPMKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.Signer != nil {
		return req.Signer, nil
	}

	if req.SigningKey == "" {
		return nil, errors.New("createSignerRequest 'signingKey' cannot be empty")
	}

	properties, err := parseNameURI(req.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.SigningKey, err)
	}

	if properties.ak {
		return nil, fmt.Errorf("signing with an AK currently not supported")
	}

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
}

// GetPublicKey returns the public key ....
func (k *TPMKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, errors.New("getPublicKeyRequest 'name' cannot be empty")
	}

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	ctx := context.Background()
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
}

// LoadCertificate loads the certificate for the key identified by name from the TPMKMS.
func (k *TPMKMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	if req.Name == "" {
		return nil, errors.New("loadCertificateRequest 'name' cannot be empty")
	}

	chain, err := k.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{Name: req.Name})
	if err != nil {
		return nil, err
	}

	return chain[0], nil
}

// LoadCertificateCertificate loads the certificate chain for the key identified by
// name from the TPMKMS.
func (k *TPMKMS) LoadCertificateChain(req *apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	if req.Name == "" {
		return nil, errors.New("loadCertificateChainRequest 'name' cannot be empty")
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
	akChain := ak.CertificateChain()
	if len(akChain) == 0 || !hasValidIdentity(ak, ekKeyURL) {
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
		if akChain, err = ac.Attest(ctx); err != nil {
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
	if !hasValidIdentity(ak, ekKeyURL) {
		return nil, fmt.Errorf("AK certificate (chain) not valid for EK %q", ekKeyURL)
	}

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
func hasValidIdentity(ak *tpm.AK, ekURL *url.URL) bool {
	chain := ak.CertificateChain()
	if len(chain) == 0 {
		return false
	}
	akCert := chain[0]

	// TODO(hs): before continuing, add check if the cert is still valid?

	// the Smallstep Attestation CA will issue AK certifiates that
	// contain the EK public key ID encoded as an URN by default.
	for _, u := range akCert.URIs {
		if ekURL.String() == u.String() {
			return true
		}
	}

	// TODO(hs): we could consider checking other values to contain
	// a usable identity too.

	return false
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

var _ apiv1.KeyManager = (*TPMKMS)(nil)
var _ apiv1.Attester = (*TPMKMS)(nil)
var _ apiv1.CertificateManager = (*TPMKMS)(nil)
var _ apiv1.CertificateChainManager = (*TPMKMS)(nil)
var _ apiv1.AttestationClient = (*attestationClient)(nil)
