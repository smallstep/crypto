//go:build windows

package platform

import (
	"context"
	"fmt"
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
		backend:      km,
		transformURI: transformToCapiKMS,
	}, nil
}

func transformToCapiKMS(u *kmsURI) string {
	uv := url.Values{
		"key": []string{u.name},
	}

	// Add custom extra values that might be tpmkms specific.
	for k, v := range u.extraValues {
		uv[k] = v
	}

	return uri.New(capi.Scheme, uv).String()
}
