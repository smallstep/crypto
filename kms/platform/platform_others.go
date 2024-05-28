//go:build !linux && !windows && !darwin

package platform

import (
	"context"
	"fmt"
	"runtime"

	"go.step.sm/crypto/kms/apiv1"
)

func newKMS(context.Context, apiv1.Options) (*KMS, error) {
	return nil, fmt.Errorf("error initializing kms: %s is not supported", runtime.GOOS)
}

func createURI(rawuri string) (string, error) {
	panic(fmt.Errorf("%s is not supported", runtime.GOOS))
}
