package platform

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.step.sm/crypto/kms/apiv1"
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
	tests := []struct {
		name      string
		rawuri    string
		want      string
		assertion assert.ErrorAssertionFunc
	}{
		{"scheme", "kms:", "mackms:", assert.NoError},
		{"with name", "kms:name=foo", "mackms:label=foo", assert.NoError},
		{"with hw", "kms:name=foo;hw=true", "mackms:keychain=dataProtection;label=foo;se=true", assert.NoError},
		{"with hw false", "kms:name=foo;hw=false", "mackms:label=foo;se=false", assert.NoError},
		{"with hw on query", "kms:name=foo?hw=true", "mackms:keychain=dataProtection;label=foo;se=true", assert.NoError},
		{"with hw and keychain", "kms:name=foo;hw=true;keychain=my", "mackms:keychain=my;label=foo;se=true", assert.NoError},
		{"with hw other", "kms:name=foo;hw=other", "mackms:label=foo", assert.NoError},
		{"with extrasValues", "kms:name=foo;keychain=my?foo=bar&baz=qux", "mackms:baz=qux;foo=bar;keychain=my;label=foo", assert.NoError},
		{"fail parse", "softkms:name=foo", "", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transformToMacKMS(tt.rawuri)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_transformFromMacKMS(t *testing.T) {
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

func TestKMS_CleanupCredentials_mackms(t *testing.T) {
	platformKMS := mustPlatformKMS(t)
	// Use an expired certificate
	chain := mustCreatePlatformCertificate(t, platformKMS, withTemplateModifier(func(c *x509.Certificate) *x509.Certificate {
		c.NotBefore = time.Now().Add(-time.Minute).Truncate(time.Second)
		c.NotAfter = time.Now().Add(-time.Second).Truncate(time.Second)
		return c
	}))

	type args struct {
		req *apiv1.CleanupCredentialsRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"not implemented", platformKMS, args{&apiv1.CleanupCredentialsRequest{
			Name:       "kms:issuer=" + chain[0].Issuer.CommonName,
			RawSubject: chain[0].RawSubject,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.ErrorIs(tt, err, apiv1.NotImplementedError{})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.CleanupCredentials(tt.args.req))
		})
	}
}
