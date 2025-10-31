//go:build !windows

package capi

import (
	"context"

	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"
)

func init() {
	apiv1.Register(apiv1.CAPIKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return nil, errors.Errorf("unsupported kms type 'capi': CAPI/nCrypt is only available on Windows, and not in WSL")
	})
}
