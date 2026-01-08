package platform

import (
	"context"
	"fmt"
	"net/url"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/mackms"
	"go.step.sm/crypto/kms/uri"
)

var _ apiv1.SearchableKeyManager = (*KMS)(nil)

func newKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	if opts.URI == "" {
		return newMacKMS(ctx, opts)
	}

	u, err := parseURI(opts.URI)
	if err != nil {
		return nil, err
	}

	switch u.backend {
	case apiv1.TPMKMS:
		return newTPMKMS(ctx, opts)
	case apiv1.DefaultKMS, apiv1.MacKMS:
		opts.URI = transformToMacKMS(u)
		return newMacKMS(ctx, opts)
	default:
		return nil, fmt.Errorf("failed parsing %q: unsupported backend %q", opts.URI, u.backend)
	}
}

func newMacKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	km, err := mackms.New(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &KMS{
		backend:      km,
		transformURI: transformToMacKMS,
	}, nil
}

func transformToMacKMS(u *kmsURI) string {
	uv := url.Values{
		"label": []string{u.name},
	}
	if u.hw {
		uv.Set("se", "true")
		uv.Set("keychain", "dataProtection")
	}

	// Add custom extra values that might be mackms specific.
	for k, v := range u.extraValues {
		uv[k] = v
	}

	return uri.New(mackms.Scheme, uv).String()
}
