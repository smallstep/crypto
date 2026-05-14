//go:build !darwin && !windows

package platform

import (
	"crypto/x509"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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

func TestKMS_CleanupCredentials_other(t *testing.T) {
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
			RawSubject: chain[0].RawSubject,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			if platformKMS.Type() == apiv1.TPMKMS {
				return assert.NoError(t, err)
			}
			return assert.ErrorIs(tt, err, apiv1.NotImplementedError{})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.CleanupCredentials(tt.args.req))
		})
	}
}
