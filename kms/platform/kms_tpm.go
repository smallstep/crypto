package platform

import (
	"context"
	"maps"
	"net/url"
	"runtime"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/tpmkms"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm"
)

var _ apiv1.Attester = (*KMS)(nil)

func newTPMKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	if opts.URI != "" {
		u, err := transformToTPMKMS(opts.URI)
		if err != nil {
			return nil, err
		}
		opts.URI = u
	}

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

func transformToTPMKMS(rawuri string) (string, error) {
	u, err := parseURI(rawuri)
	if err != nil {
		return "", err
	}

	uv := url.Values{}
	if u.name != "" {
		uv.Set("name", u.name)
	}

	// When storing a certificate on windows, skip key validation. This avoid a
	// prompt looking for an SmartCard.
	if runtime.GOOS == "windows" && !u.extraValues.Has("skip-find-certificate-key") {
		uv.Set("skip-find-certificate-key", "true")
	}

	// Add custom extra values that might be tpmkms specific.
	// There is not need to set "hw".
	maps.Copy(uv, u.extraValues)

	return uri.New(tpmkms.Scheme, uv).String(), nil
}

func transformFromTPMKMS(rawuri string) (string, error) {
	u, err := uri.ParseWithScheme(tpmkms.Scheme, rawuri)
	if err != nil {
		return "", err
	}

	uv := url.Values{}
	if u.Has("name") {
		uv.Set(nameKey, u.Get("name"))
	}

	for k, v := range uri.Values(u) {
		if k != nameKey {
			uv[k] = v
		}
	}

	return uri.New(Scheme, uv).String(), nil
}
