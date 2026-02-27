package platform

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
)

const Scheme = "kms"

func init() {
	apiv1.Register(apiv1.PlatformKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

const (
	backendKey = "backend"
	nameKey    = "name"
	hwKey      = "hw"
)

type kmsURI struct {
	uri         *uri.URI
	backend     apiv1.Type
	name        string
	hw          bool
	extraValues url.Values
}

func parseURI(rawuri string) (*kmsURI, error) {
	u, err := uri.ParseWithScheme(Scheme, rawuri)
	if err != nil {
		return nil, err
	}

	extraValues := make(url.Values)
	for k, v := range u.Values {
		if k != nameKey && k != hwKey && k != backendKey {
			extraValues[k] = v
		}
	}

	return &kmsURI{
		uri:         u,
		backend:     apiv1.Type(strings.ToLower(u.Get(backendKey))),
		name:        u.Get(nameKey),
		hw:          u.GetBool(hwKey),
		extraValues: extraValues,
	}, nil
}

type extendedKeyManager interface {
	apiv1.KeyManager
	apiv1.KeyDeleter
	apiv1.CertificateManager
	apiv1.CertificateChainManager
	apiv1.CertificateDeleter
}

var _ apiv1.KeyManager = (*KMS)(nil)
var _ apiv1.CertificateManager = (*KMS)(nil)
var _ apiv1.CertificateChainManager = (*KMS)(nil)

type KMS struct {
	typ              apiv1.Type
	backend          extendedKeyManager
	transformToURI   func(*kmsURI) string
	transformFromURI func(string) (string, error)
}

func New(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	return newKMS(ctx, opts)
}

func (k *KMS) Type() apiv1.Type {
	return k.typ
}

func (k *KMS) Close() error {
	return k.backend.Close()
}

func (k *KMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	name, err := k.transform(req.Name)
	if err != nil {
		return nil, err
	}
	return k.backend.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: name,
	})
}

func (k *KMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	name, err := k.transform(req.Name)
	if err != nil {
		return nil, err
	}

	r := clone(req)
	r.Name = name
	resp, err := k.backend.CreateKey(r)
	if err != nil {
		return nil, err
	}

	return k.patchCreateKeyResponse(resp)
}

func (k *KMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.Signer != nil {
		return req.Signer, nil
	}

	signingKey, err := k.transform(req.SigningKey)
	if err != nil {
		return nil, err
	}

	r := clone(req)
	r.SigningKey = signingKey
	return k.backend.CreateSigner(r)
}

func (k *KMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	name, err := k.transform(req.Name)
	if err != nil {
		return err
	}

	r := clone(req)
	r.Name = name
	return k.backend.DeleteKey(r)
}

func (k *KMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	name, err := k.transform(req.Name)
	if err != nil {
		return nil, err
	}

	r := clone(req)
	r.Name = name
	return k.backend.LoadCertificate(r)
}

func (k *KMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	name, err := k.transform(req.Name)
	if err != nil {
		return err
	}

	r := clone(req)
	r.Name = name
	return k.backend.StoreCertificate(r)
}

func (k *KMS) LoadCertificateChain(req *apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	name, err := k.transform(req.Name)
	if err != nil {
		return nil, err
	}

	r := clone(req)
	r.Name = name
	return k.backend.LoadCertificateChain(r)
}

func (k *KMS) StoreCertificateChain(req *apiv1.StoreCertificateChainRequest) error {
	name, err := k.transform(req.Name)
	if err != nil {
		return err
	}

	r := clone(req)
	r.Name = name
	return k.backend.StoreCertificateChain(r)
}

func (k *KMS) DeleteCertificate(req *apiv1.DeleteCertificateRequest) error {
	name, err := k.transform(req.Name)
	if err != nil {
		return err
	}

	r := clone(req)
	r.Name = name
	return k.backend.DeleteCertificate(r)
}

func (k *KMS) CreateAttestation(req *apiv1.CreateAttestationRequest) (*apiv1.CreateAttestationResponse, error) {
	if req.Name == "" {
		return nil, errors.New("createAttestationRequest 'name' cannot be empty")
	}

	name, err := k.transform(req.Name)
	if err != nil {
		return nil, err
	}

	// Attestation implemented by the backend
	if km, ok := k.backend.(apiv1.Attester); ok {
		r := clone(req)
		r.Name = name

		return km.CreateAttestation(r)
	}

	// Attestation using a custom attestation client.
	if req.AttestationClient != nil {
		signer, err := k.backend.CreateSigner(&apiv1.CreateSignerRequest{
			SigningKey: name,
		})
		if err != nil {
			return nil, err
		}

		ctx := apiv1.NewAttestSignerContext(context.Background(), signer)
		chain, err := req.AttestationClient.Attest(ctx)
		if err != nil {
			return nil, err
		}

		var permanentIdentifier string
		if len(chain[0].URIs) > 0 {
			permanentIdentifier = chain[0].URIs[0].String()
		}

		return &apiv1.CreateAttestationResponse{
			Certificate:         chain[0],
			CertificateChain:    chain,
			PublicKey:           signer.Public(),
			PermanentIdentifier: permanentIdentifier,
		}, nil
	}

	return nil, apiv1.NotImplementedError{}
}

func (k *KMS) SearchKeys(req *apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error) {
	if km, ok := k.backend.(apiv1.SearchableKeyManager); ok {
		query, err := k.transform(req.Query)
		if err != nil {
			return nil, err
		}

		r := clone(req)
		r.Query = query
		resp, err := km.SearchKeys(r)
		if err != nil {
			return nil, err
		}

		return k.patchSearchKeysResponse(resp)
	}

	return nil, apiv1.NotImplementedError{}
}

func (k *KMS) transform(rawuri string) (string, error) {
	u, err := parseURI(rawuri)
	if err != nil {
		return "", err
	}

	return k.transformToURI(u), nil
}

func (k *KMS) patchCreateKeyResponse(resp *apiv1.CreateKeyResponse) (*apiv1.CreateKeyResponse, error) {
	name, err := k.transformFromURI(resp.Name)
	if err != nil {
		return nil, err
	}

	resp.Name = name
	if resp.CreateSignerRequest.SigningKey != "" {
		resp.CreateSignerRequest.SigningKey = name
	}

	return resp, nil
}

func (k *KMS) patchSearchKeysResponse(resp *apiv1.SearchKeysResponse) (*apiv1.SearchKeysResponse, error) {
	for i := range resp.Results {
		name, err := k.transformFromURI(resp.Results[i].Name)
		if err != nil {
			return nil, err
		}

		resp.Results[i].Name = name
		if resp.Results[i].CreateSignerRequest.SigningKey != "" {
			resp.Results[i].CreateSignerRequest.SigningKey = name
		}
	}

	return resp, nil
}

func clone[T any](v *T) *T {
	c := *v
	return &c
}
