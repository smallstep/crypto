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

const tpmProvider = "Microsoft Platform Crypto Provider"

func newKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	backend, err := getBackend(opts)
	if err != nil {
		return nil, err
	}

	switch backend {
	case apiv1.CAPIKMS:
		return newCAPIKMS(ctx, opts)
	case apiv1.SoftKMS:
		return newSoftKMS(ctx, opts)
	case apiv1.PlatformKMS, apiv1.DefaultKMS, apiv1.TPMKMS:
		// Add enable-cng=true if necessary
		if opts.URI, err = withEnableCNG(opts.URI); err != nil {
			return nil, err
		}
		return newTPMKMS(ctx, opts)
	default:
		return nil, fmt.Errorf("failed parsing options: unsupported backend %q", backend)
	}
}

func newCAPIKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	if opts.URI != "" {
		u, err := transformToCAPIKMS(opts.URI)
		if err != nil {
			return nil, err
		}
		opts.URI = u
	}

	km, err := capi.New(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &KMS{
		typ:              apiv1.CAPIKMS,
		backend:          km,
		transformToURI:   transformToCAPIKMS,
		transformFromURI: transformFromCAPIKMS,
	}, nil
}

func withEnableCNG(rawuri string) (string, error) {
	if rawuri == "" {
		return "kms:enable-cng=true", nil
	}

	u, err := uri.ParseWithScheme(Scheme, rawuri)
	if err != nil {
		return "", err
	}

	if !u.Has("enable-cng") {
		u.Set("enable-cng", "true")
	}
	return u.String(), nil
}

func transformToCAPIKMS(rawuri string) (string, error) {
	u, err := parseURI(rawuri)
	if err != nil {
		return "", err
	}

	uv := url.Values{}
	if u.name != "" {
		uv.Set("key", u.name)
	}

	// When storing certificate skip key validation.
	// This avoid a prompt looking for an SmartCard.
	if !u.extraValues.Has("skip-find-certificate-key") {
		uv.Set("skip-find-certificate-key", "true")
	}

	// Set provider "Microsoft Platform Crypto Provider" to use the TPM.
	if u.hw && !u.extraValues.Has("provider") {
		uv.Set("provider", tpmProvider)
	}

	// Add custom extra values that might be CAPI specific.
	maps.Copy(uv, u.extraValues)

	return uri.New(capi.Scheme, uv).String(), nil
}

func transformFromCAPIKMS(rawuri string) (string, error) {
	u, err := uri.ParseWithScheme(capi.Scheme, rawuri)
	if err != nil {
		return "", err
	}

	uv := url.Values{}
	if u.Has("key") {
		uv.Set("name", u.Get("key"))
	}
	if u.Get("provider") == tpmProvider {
		uv.Set("hw", "true")
	}

	for k, v := range uri.Values(u) {
		if k != "key" {
			uv[k] = v
		}
	}

	return uri.New(Scheme, uv).String(), nil
}
