package platform

import "testing"

func mustPlatformKMS(t *testing.T) *KMS {
	t.Helper()

	return mustKMS(t, "kms:")
}

// SkipTest is a method implemented on tests that allow skipping the test on
// this platform.
func (k *KMS) SkipTests() bool {
	return false
}
