package platform

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"strings"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/mackms"
	"go.step.sm/crypto/kms/uri"
)

var _ apiv1.SearchableKeyManager = (*KMS)(nil)

func newKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	backend, err := getBackend(opts)
	if err != nil {
		return nil, err
	}

	switch backend {
	case apiv1.TPMKMS:
		return newTPMKMS(ctx, opts)
	case apiv1.SoftKMS:
		return newSoftKMS(ctx, opts)
	case apiv1.DefaultKMS, apiv1.MacKMS:
		return newMacKMS(ctx, opts)
	default:
		return nil, fmt.Errorf("failed parsing options: unsupported backend %q", backend)
	}
}

func newMacKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	if opts.URI != "" {
		u, err := transformToMacKMS(opts.URI)
		if err != nil {
			return nil, fmt.Errorf("error parsing uri: %w", err)
		}
		opts.URI = u
	}

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

func transformToMacKMS(rawuri string) (string, error) {
	u, err := parseURI(rawuri)
	if err != nil {
		return "", err
	}

	uv := url.Values{}
	if u.name != "" {
		uv.Set("label", u.name)
	}
	if u.hw {
		uv.Set("se", "true")
		if !u.uri.Has("keychain") {
			uv.Set("keychain", "dataProtection")
		}
	} else if strings.EqualFold(u.uri.Get("hw"), "false") {
		uv.Set("se", "false")
	}

	// Add custom extra values that might be mackms specific.
	maps.Copy(uv, u.extraValues)

	return uri.New(mackms.Scheme, uv).String(), nil
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
