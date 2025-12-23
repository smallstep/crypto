//go:build windows

package platform

import (
	"context"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/capi"
	"go.step.sm/crypto/kms/uri"
)

func newKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	if opts.Type == apiv1.CAPIKMS {
		km, err := capi.New(ctx, opts)
		if err != nil {
			return nil, err
		}

		return &KMS{
			backend: km,
		}, nil
	}

	if opts.URI != "" {
		u, err := uri.Parse(opts.URI)
		if err != nil {
			return nil, err
		}

		if !u.Has("enable-cng") {
			u.Values.Set("enable-cng", "true")
		}
		opts.URI = u.String()
	}

	return newTPMKMS(ctx, opts)
}
