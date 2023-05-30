//go:build !notpmkms
// +build !notpmkms

package tpmkms

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

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

// TPMKMS is a KMS implementation backed by a TPM.
type TPMKMS struct {
	tpm                   *tpm.TPM
	attestationCABaseURL  string
	attestationCARootFile string
	attestationCAInsecure bool
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

// New returns a new TPM KMS.
func New(ctx context.Context, opts apiv1.Options) (kms *TPMKMS, err error) {
	kms = &TPMKMS{}
	tpmOpts := []tpm.NewTPMOption{tpm.WithStore(storage.BlackHole())} // TODO: use some default storage location instead?
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
	}

	kms.tpm, err = tpm.New(tpmOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed creating new TPM: %w", err)
	}

	return
}

// CreateKey generates a new key in the TPM KMS and returns the public key.
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

	size := 2048
	if req.Bits > 0 {
		size = req.Bits
	}

	if v.Type == "ECDSA" {
		size = v.Curve
	}

	ctx := context.Background()
	if properties.ak {
		ak, err := k.tpm.CreateAK(ctx, properties.name)
		if err != nil {
			if errors.Is(err, tpm.ErrExists) {
				return nil, apiv1.AlreadyExistsError{Message: err.Error()}
			}
			return nil, fmt.Errorf("failed creating AK: %w", err)
		}
		createdAKURI := fmt.Sprintf("tpmkms:name=%s;ak=true", ak.Name())
		return &apiv1.CreateKeyResponse{
			Name: createdAKURI,
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

	priv, ok := signer.(crypto.PrivateKey)
	if !ok {
		return nil, errors.New("failed getting private key")
	}

	createdKeyURI := fmt.Sprintf("tpmkms:name=%s", key.Name())
	if properties.attestBy != "" {
		createdKeyURI = fmt.Sprintf("%s;attest-by=%s", createdKeyURI, key.AttestedBy())
	}

	return &apiv1.CreateKeyResponse{
		Name:       createdKeyURI,
		PublicKey:  signer.Public(),
		PrivateKey: priv,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: createdKeyURI,
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

	if properties.ak {
		return nil, fmt.Errorf("retrieving AK public key currently not supported")
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

	return signer.Public(), nil
}

func (k *TPMKMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	if req.Name == "" {
		return nil, errors.New("loadCertificateRequest 'name' cannot be empty")
	}

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	ctx := context.Background()
	var cert *x509.Certificate // TODO: support returning chain?
	if properties.ak {
		ak, err := k.tpm.GetAK(ctx, properties.name)
		if err != nil {
			return nil, err
		}
		cert = ak.Certificate()
	} else {
		key, err := k.tpm.GetKey(ctx, properties.name)
		if err != nil {
			return nil, err
		}
		cert = key.Certificate()
	}

	if cert == nil {
		return nil, fmt.Errorf("failed getting certificate for %q: no certificate stored", properties.name)
	}

	return cert, nil
}
func (k *TPMKMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	if req.Name == "" {
		return errors.New("storeCertificateRequest 'name' cannot be empty")
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
		err = ak.SetCertificateChain(ctx, []*x509.Certificate{req.Certificate})
		if err != nil {
			return fmt.Errorf("failed storing certificate for AK %q: %w", properties.name, err)
		}
	} else {
		key, err := k.tpm.GetKey(ctx, properties.name)
		if err != nil {
			return err
		}

		err = key.SetCertificateChain(ctx, []*x509.Certificate{req.Certificate}) // TODO: support chain in request?
		if err != nil {
			return fmt.Errorf("failed storing certificate for key %q: %w", properties.name, err)
		}
	}

	return nil
}

type attestationClient struct {
	c  *attestation.Client
	t  *tpm.TPM
	ek *tpm.EK
	ak *tpm.AK
}

func (k *TPMKMS) newAttestorClient(ek *tpm.EK, ak *tpm.AK) (*attestationClient, error) {
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

func (ac *attestationClient) Attest(ctx context.Context) ([]*x509.Certificate, error) {
	return ac.c.Attest(ctx, ac.t, ac.ek, ac.ak)
}

func (k *TPMKMS) CreateAttestation(req *apiv1.CreateAttestationRequest) (*apiv1.CreateAttestationResponse, error) {
	if req.Name == "" {
		return nil, errors.New("CreateAttestationRequest 'name' cannot be empty")
	}

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}

	ctx := context.Background()
	key, err := k.tpm.GetKey(ctx, properties.name)
	if err != nil {
		return nil, fmt.Errorf("failed getting key %q: %w", properties.name, err)
	}

	if !key.WasAttested() {
		return nil, fmt.Errorf("key %q was not attested", key.Name())
	}

	ak, err := k.tpm.GetAK(ctx, key.AttestedBy())
	if err != nil {
		return nil, fmt.Errorf("failed getting AK for key %q: %w", key.Name(), err)
	}

	// TODO: verify the below logic is OK and complete
	akChain := ak.CertificateChain()
	if len(akChain) > 0 {
		akCert := akChain[0]
		resp := &apiv1.CreateAttestationResponse{
			Certificate:      akCert,           // TODO: verify this is the correct one to set here
			CertificateChain: akChain,          // TODO: verify this is the correct one to set here
			PublicKey:        akCert.PublicKey, // TODO: verify this is the correct one to set here
			// PermanentIdentifier string
		}

		return resp, nil
	}

	// TODO: check if there's a certificate available already. If not, try
	// creating an attestation by enrolling with an attestation CA; return the
	// certificate, chain, public key and permanent identifier if successful.
	// How to provide the attestation CA details? At KMS initialization time?
	// With the CreateAttestationRequest? Parsed from the name, or a new property?
	// New property somewhat makes sense to me.

	// TODO: only perform the below call to Attest() when required, so when
	// no attestation chain with for the right values / identifiers is available yet.
	var ac apiv1.AttestationClient
	if req.AttestationClient != nil {
		// TODO: check if it makes sense to have this; it doesn't capture all
		// behaviour that the built-in attestorClient does.
		ac = req.AttestationClient
	} else {
		eks, err := k.tpm.GetEKs(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed getting EKs: %w", err)
		}
		ek := getPreferredEK(eks)
		ac, err = k.newAttestorClient(ek, ak)
		if err != nil {
			return nil, fmt.Errorf("failed creating attestor client: %w", err)
		}
	}

	akChain, err = ac.Attest(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed attesting AK for key %q: %w", key.Name(), err)
	}

	// store the result with the AK, so that it can be reused for future
	// attestations.
	if err := ak.SetCertificateChain(ctx, akChain); err != nil {
		return nil, fmt.Errorf("failed storing AK certificate: %w", err)
	}

	akCert := akChain[0]
	resp := &apiv1.CreateAttestationResponse{
		Certificate:      akCert,           // TODO: verify this is the correct one to set here
		CertificateChain: akChain,          // TODO: verify this is the correct one to set here
		PublicKey:        akCert.PublicKey, // TODO: verify this is the correct one to set here
		// PermanentIdentifier string
	}

	return resp, nil
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

var _ apiv1.KeyManager = (*TPMKMS)(nil)
var _ apiv1.Attester = (*TPMKMS)(nil)
var _ apiv1.CertificateManager = (*TPMKMS)(nil)
var _ apiv1.AttestationClient = (*attestationClient)(nil)
