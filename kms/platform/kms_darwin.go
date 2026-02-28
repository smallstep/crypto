package platform

import (
	"context"
	"fmt"
	"maps"
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
	case apiv1.SoftKMS:
		return newSoftKMS(ctx, opts)
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
		typ:              apiv1.MacKMS,
		backend:          km,
		transformToURI:   transformToMacKMS,
		transformFromURI: transformFromMacKMS,
	}, nil
}

func transformToMacKMS(u *kmsURI) string {
	uv := url.Values{}
	if u.name != "" {
		uv.Set("label", u.name)
	}
	if u.hw {
		uv.Set("se", "true")
		if !u.uri.Has("keychain") {
			uv.Set("keychain", "dataProtection")
		}
	} else if u.uri.Has("hw") {
		uv.Set("se", "false")
	}

	// Add custom extra values that might be mackms specific.
	maps.Copy(uv, u.extraValues)

	return uri.New(mackms.Scheme, uv).String()
}

func transformFromMacKMS(rawuri string) (string, error) {
	u, err := uri.ParseWithScheme(mackms.Scheme, rawuri)
	if err != nil {
		return "", err
	}

	uv := url.Values{}
	if u.Has("label") {
		uv.Set("name", u.Get("label"))
	}
	if u.GetBool("se") {
		uv.Set("hw", "true")
	}

	for k, v := range uri.Values(u) {
		if k != "label" && k != "se" {
			uv[k] = v
		}
	}

	return uri.New(Scheme, uv).String(), nil
}
