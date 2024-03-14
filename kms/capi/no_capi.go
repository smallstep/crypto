//go:build !windows || nocapi
// +build !windows nocapi

package cloudkms

import (
	"context"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"
)

func init() {
	apiv1.Register(apiv1.CAPIKMS, func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		name := filepath.Base(os.Args[0])
		return nil, errors.Errorf("unsupported kms type 'capi': %s is compiled without Microsoft CryptoAPI support", name)
	})
}
