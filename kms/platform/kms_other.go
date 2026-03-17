//go:build !darwin && !windows

package platform

import (
	"context"
	"fmt"

	"go.step.sm/crypto/kms/apiv1"
)

func newKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	backend, err := getBackend(opts)
	if err != nil {
		return nil, err
	}

	switch backend {
	case apiv1.SoftKMS:
		return newSoftKMS(ctx, opts)
	case apiv1.DefaultKMS, apiv1.TPMKMS:
		return newTPMKMS(ctx, opts)
	default:
		return nil, fmt.Errorf("failed parsing options: unsupported backend %q", backend)
	}
}
