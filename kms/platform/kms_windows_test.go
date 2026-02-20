//go:build windows

package platform

import (
	"testing"
)

func mustPlatformKMS(t *testing.T) *KMS {
	return &KMS{}
}

// SkipTest is a method implemented on tests that allow skipping the test on
// this platform.
func (k *KMS) SkipTests() bool {
	return true
}
