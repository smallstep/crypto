package platform

import (
	"context"
	"maps"
	"net/url"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/tpmkms"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm"
)

var _ apiv1.Attester = (*KMS)(nil)

func newTPMKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	if opts.URI == "" {
		return newTPMKMS(ctx, opts)
	}

	u, err := parseURI(opts.URI)
	if err != nil {
		return nil, err
	}

	opts.URI = transformToTPMKMS(u)
	km, err := tpmkms.New(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &KMS{
		typ:              apiv1.TPMKMS,
		backend:          km,
		transformToURI:   transformToTPMKMS,
		transformFromURI: transformFromTPMKMS,
	}, nil
}

func NewWithTPM(ctx context.Context, t *tpm.TPM, opts ...tpmkms.Option) (*KMS, error) {
	km, err := tpmkms.NewWithTPM(ctx, t, opts...)
	if err != nil {
		return nil, err
	}

	return &KMS{
		typ:              apiv1.TPMKMS,
		backend:          km,
		transformToURI:   transformToTPMKMS,
		transformFromURI: transformFromTPMKMS,
	}, nil
}

func (k *KMS) CreateAttestation(req *apiv1.CreateAttestationRequest) (*apiv1.CreateAttestationResponse, error) {
	if km, ok := k.backend.(apiv1.Attester); ok {
		return km.CreateAttestation(req)
	}

	return nil, apiv1.NotImplementedError{}
}

func transformToTPMKMS(u *kmsURI) string {
	uv := url.Values{}
	if u.name != "" {
		uv.Set("name", u.name)
	}
	if u.hw {
		uv.Set("ak", "true")
	} else if u.uri.Has("hw") {
		uv.Set("ak", "false")
	}

	// Add custom extra values that might be tpmkms specific.
	maps.Copy(uv, u.extraValues)

	return uri.New(tpmkms.Scheme, uv).String()
}

func transformFromTPMKMS(rawuri string) (string, error) {
	u, err := uri.ParseWithScheme(tpmkms.Scheme, rawuri)
	if err != nil {
		return "", err
	}

	uv := url.Values{
		"name": []string{u.Get("name")},
	}
	if u.GetBool("ak") {
		uv.Set("hw", "true")
	}

	for k, v := range u.Values {
		if k != "name" && k != "ak" {
			uv[k] = v
		}
	}

	return uri.New(Scheme, uv).String(), nil
}
