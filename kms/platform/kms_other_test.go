//go:build !darwin && !windows

package platform

import (
	"net/url"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm/available"
)

func mustPlatformKMS(t *testing.T) *KMS {
	if available.Check() != nil {
		return &KMS{}
	}

	return mustKMS(t, uri.New(Scheme, url.Values{
		"storage-directory": []string{t.TempDir()},
	}).String())
}

// SkipTest is a method implemented on tests that allow skipping the test on
// this platform.
func (k *KMS) SkipTests() bool {
	return k.Type() == apiv1.DefaultKMS
}
