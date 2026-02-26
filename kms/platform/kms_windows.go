//go:build windows

package platform

import (
	"context"
	"fmt"
	"maps"
	"net/url"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/capi"
	"go.step.sm/crypto/kms/uri"
)

func newKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	if opts.URI == "" {
		return newTPMKMS(ctx, opts)
	}

	u, err := parseURI(opts.URI)
	if err != nil {
		return nil, err
	}

	switch u.backend {
	case apiv1.CAPIKMS:
		opts.URI = transformToCapiKMS(u)
		return newCAPIKMS(ctx, opts)
	case apiv1.SoftKMS:
		return newSoftKMS(ctx, opts)
	case apiv1.DefaultKMS, apiv1.TPMKMS:
		return newTPMKMS(ctx, opts)
	default:
		return nil, fmt.Errorf("failed parsing %q: unsupported backend %q", opts.URI, u.backend)
	}
}

func newCAPIKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	km, err := capi.New(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &KMS{
		typ:              apiv1.CAPIKMS,
		backend:          km,
		transformToURI:   transformToCapiKMS,
		transformFromURI: transformFromCapiKMS,
	}, nil
}

func transformToCapiKMS(u *kmsURI) string {
	uv := url.Values{}
	if u.name != "" {
		uv.Set("key", u.name)
	}

	// When storing certificate skip key validation.
	// This avoid a prompt looking for an SmartCard.
	uv.Set("skip-find-certificate-key", "true")

	// Add custom extra values that might be CAPI specific.
	maps.Copy(uv, u.extraValues)

	return uri.New(capi.Scheme, uv).String()
}

func transformFromCapiKMS(rawuri string) (string, error) {
	u, err := uri.ParseWithScheme(capi.Scheme, rawuri)
	if err != nil {
		return "", err
	}

	uv := url.Values{
		"name": []string{u.Get("key")},
	}

	for k, v := range u.Values {
		if k != "key" {
			uv[k] = v
		}
	}

	return uri.New(Scheme, uv).String(), nil
}
