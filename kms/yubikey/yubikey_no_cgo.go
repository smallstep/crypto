//go:build !cgo || noyubikey
// +build !cgo noyubikey

package yubikey

import (
	"context"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"
)

func init() {
	apiv1.Register(apiv1.YubiKey, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		name := filepath.Base(os.Args[0])
		return nil, errors.Errorf("unsupported kms type 'yubikey': %s is compiled without cgo or YubiKey support", name)
	})
}
