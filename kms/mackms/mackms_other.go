//go:build !cgo || !darwin || nomackms

package mackms

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"go.step.sm/crypto/kms/apiv1"
)

func init() {
	apiv1.Register(apiv1.MacKMS, func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		name := filepath.Base(os.Args[0])
		switch runtime.GOOS {
		case "darwin":
			return nil, fmt.Errorf("unsupported kms type 'mackms': %q is compiled without cgo or mackms support", name)
		default:
			return nil, fmt.Errorf("unsupported kms type 'mackms': %q is not running on a macOS", name)
		}
	})
}
