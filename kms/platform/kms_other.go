//go:build !darwin && !windows

package platform

import (
	"context"
	"fmt"

	"go.step.sm/crypto/kms/apiv1"
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
	case apiv1.SoftKMS:
		return newSoftKMS(ctx, opts)
	case apiv1.DefaultKMS, apiv1.TPMKMS:
		return newTPMKMS(ctx, opts)
	default:
		return nil, fmt.Errorf("failed parsing %q: unsupported backend %q", opts.URI, u.backend)
	}
}
