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
	if opts.URI == "" {
		return newTPMKMS(ctx, opts)
	}

	u, err := parseURI(opts.URI)
	if err != nil {
		return nil, err
	}

	switch u.backend {
	case apiv1.CAPIKMS:
		opts.URI = transformToCAPIKMS(u)
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
		transformToURI:   transformToCAPIKMS,
		transformFromURI: transformFromCAPIKMS,
	}, nil
}

func transformToCAPIKMS(u *kmsURI) string {
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

	return uri.New(capi.Scheme, uv).String()
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
