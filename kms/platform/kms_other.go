//go:build !darwin && !windows

package platform

import (
	"context"

	"go.step.sm/crypto/kms/apiv1"
)

func newKMS(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	return newTPMKMS(ctx, opts)
}
