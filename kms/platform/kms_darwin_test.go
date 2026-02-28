package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func mustPlatformKMS(t *testing.T) *KMS {
	t.Helper()

	return mustKMS(t, "kms:")
}

// SkipTest is a method implemented on tests that allow skipping the test on
// this platform.
func (k *KMS) SkipTests() bool {
	return false
}

func Test_transformToMacKMS(t *testing.T) {
	type args struct {
		u *kmsURI
	}
	tests := []struct {
		name   string
		rawuri string
		want   string
	}{
		{"scheme", "kms:", "mackms:"},
		{"with name", "kms:name=foo", "mackms:label=foo"},
		{"with hw", "kms:name=foo;hw=true", "mackms:keychain=dataProtection;label=foo;se=true"},
		{"with hw on query", "kms:name=foo?hw=true", "mackms:keychain=dataProtection;label=foo;se=true"},
		{"with hw and keychain", "kms:name=foo;hw=true;keychain=my", "mackms:keychain=my;label=foo;se=true"},
		{"with extrasValues", "kms:name=foo;keychain=my?foo=bar&baz=qux", "mackms:baz=qux;foo=bar;keychain=my;label=foo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := mustParseURI(t, tt.rawuri)
			assert.Equal(t, tt.want, transformToMacKMS(u))
		})
	}
}

func Test_transformFromMacKMS(t *testing.T) {
	type args struct {
		rawuri string
	}
	tests := []struct {
		name      string
		rawuri    string
		want      string
		assertion assert.ErrorAssertionFunc
	}{
		{"scheme", "mackms:", "kms:", assert.NoError},
		{"with label", "mackms:label=foo", "kms:name=foo", assert.NoError},
		{"with se", "mackms:label=foo;se=true", "kms:hw=true;name=foo", assert.NoError},
		{"with se on query", "mackms:label=foo?se=true", "kms:hw=true;name=foo", assert.NoError},
		{"with keychain", "mackms:label=foo;se=true;keychain=dataProtection", "kms:hw=true;keychain=dataProtection;name=foo", assert.NoError},
		{"with keychain on query", "mackms:label=foo?keychain=dataProtection&foo=bar", "kms:foo=bar;keychain=dataProtection;name=foo", assert.NoError},
		{"fail empty", "", "", assert.Error},
		{"fail scheme", "kms:", "", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transformFromMacKMS(tt.rawuri)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
