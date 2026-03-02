//go:build windows

package platform

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm/available"
)

func mustPlatformKMS(t *testing.T) *KMS {
	t.Helper()

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

func mustCAPIKMS(t *testing.T) *KMS {
	return mustKMS(t, "kms:backend=capi")
}

func TestKMS_Type_capi(t *testing.T) {
	km := mustCAPIKMS(t)
	assert.Equal(t, apiv1.CAPIKMS, km.Type())
}

func TestKMS_GetPublicKey_capi(t *testing.T) {
	capiKMS := mustCAPIKMS(t)
	capiKey := mustCreatePlatformKey(t, capiKMS)

	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      crypto.PublicKey
		assertion assert.ErrorAssertionFunc
	}{
		{"ok capi", capiKMS, args{&apiv1.GetPublicKeyRequest{
			Name: capiKey.Name,
		}}, capiKey.PublicKey, assert.NoError},
		{"fail capi missing", capiKMS, args{&apiv1.GetPublicKeyRequest{
			Name: platformMissingName,
		}}, nil, assert.Error},
		{"fail capi name", capiKMS, args{&apiv1.GetPublicKeyRequest{
			Name: "kms:something=test",
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.GetPublicKey(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKMS_CreateKey_capi(t *testing.T) {
	suffix := mustSuffix(t)
	capiKMS := mustCAPIKMS(t)

	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		equal     func(t *testing.T, got *apiv1.CreateKeyResponse)
		assertion assert.ErrorAssertionFunc
	}{
		{"ok capi", capiKMS, args{&apiv1.CreateKeyRequest{
			Name: "kms:name=test1-" + suffix,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			require.NotNil(t, got)

			t.Cleanup(func() {
				assert.NoError(t, capiKMS.DeleteKey(&apiv1.DeleteKeyRequest{
					Name: "kms:name=test1-" + suffix,
				}))
			})

			assert.Regexp(t, "^kms:.*name=.*;provider=.*$", got.Name)
			assert.Equal(t, got.Name, got.CreateSignerRequest.SigningKey)

			if capiKMS.Type() == apiv1.TPMKMS && assert.IsType(t, &rsa.PublicKey{}, got.PublicKey) {
				assert.Equal(t, 256, got.PublicKey.(*rsa.PublicKey).Size())
			} else if assert.IsType(t, &ecdsa.PublicKey{}, got.PublicKey) {
				assert.Equal(t, elliptic.P256(), got.PublicKey.(*ecdsa.PublicKey).Curve)
			}
		}, assert.NoError},
		{"ok capi ECDSA", capiKMS, args{&apiv1.CreateKeyRequest{
			Name:               "kms:name=test2-" + suffix,
			SignatureAlgorithm: apiv1.ECDSAWithSHA384,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			require.NotNil(t, got)

			t.Cleanup(func() {
				assert.NoError(t, capiKMS.DeleteKey(&apiv1.DeleteKeyRequest{
					Name: "kms:name=test2-" + suffix,
				}))
			})

			assert.Regexp(t, "^kms:.*name=.*;provider=.*$", got.Name)
			assert.Equal(t, got.Name, got.CreateSignerRequest.SigningKey)

			if assert.IsType(t, &ecdsa.PublicKey{}, got.PublicKey) {
				assert.Equal(t, elliptic.P384(), got.PublicKey.(*ecdsa.PublicKey).Curve)
			}
		}, assert.NoError},
		{"ok capi RSA", capiKMS, args{&apiv1.CreateKeyRequest{
			Name:               "kms:name=test3-" + suffix,
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               2048,
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			require.NotNil(t, got)

			t.Cleanup(func() {
				assert.NoError(t, capiKMS.DeleteKey(&apiv1.DeleteKeyRequest{
					Name: "kms:name=test3-" + suffix,
				}))
			})

			assert.Regexp(t, "^kms:.*name=.*;provider=.*$", got.Name)
			assert.Equal(t, got.Name, got.CreateSignerRequest.SigningKey)
			if assert.IsType(t, &rsa.PublicKey{}, got.PublicKey) {
				assert.Equal(t, 256, got.PublicKey.(*rsa.PublicKey).Size())
			}
		}, assert.NoError},
		{"fail capi algorithm", capiKMS, args{&apiv1.CreateKeyRequest{
			Name:               "kms:test4-" + suffix,
			SignatureAlgorithm: apiv1.SignatureAlgorithm(100),
		}}, func(t *testing.T, got *apiv1.CreateKeyResponse) {
			assert.Nil(t, got)
		}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.CreateKey(tt.args.req)
			tt.assertion(t, err)
			tt.equal(t, got)
		})
	}
}

func TestKMS_CreateSigner_capi(t *testing.T) {
	capiKMS := mustCAPIKMS(t)
	capiKey := mustCreatePlatformKey(t, capiKMS)

	assertNil := func(t *testing.T, got crypto.Signer) {
		t.Helper()
		assert.Nil(t, got)
	}

	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		equal     func(*testing.T, crypto.Signer)
		assertion assert.ErrorAssertionFunc
	}{
		{"ok capi", capiKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: platformKeyName,
		}}, func(t *testing.T, s crypto.Signer) {
			require.NotNil(t, s)
			assert.Equal(t, capiKey.PublicKey, s.Public())
		}, assert.NoError},
		{"fail capi missing", capiKMS, args{&apiv1.CreateSignerRequest{
			SigningKey: platformMissingName,
		}}, assertNil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.CreateSigner(tt.args.req)
			tt.assertion(t, err)
			tt.equal(t, got)
		})
	}
}

func TestKMS_DeleteKey_capi(t *testing.T) {
	capiKMS := mustCAPIKMS(t)
	capiKey := mustCreatePlatformKey(t, capiKMS, withNoCleanup())

	type args struct {
		req *apiv1.DeleteKeyRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok capi", capiKMS, args{&apiv1.DeleteKeyRequest{
			Name: capiKey.Name,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			_, getErr := capiKMS.GetPublicKey(&apiv1.GetPublicKeyRequest{
				Name: capiKey.Name,
			})
			return assert.NoError(t, err) && assert.Error(t, getErr)
		}},
		{"fail capi deleted", capiKMS, args{&apiv1.DeleteKeyRequest{
			Name: capiKey.Name,
		}}, assert.Error},
		{"fail capi missing", capiKMS, args{&apiv1.DeleteKeyRequest{
			Name: platformMissingName,
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.DeleteKey(tt.args.req))
		})
	}
}

func TestKMS_LoadCertificate_capi(t *testing.T) {
	capiKMS := mustCAPIKMS(t)
	capiKey := mustCreatePlatformKey(t, capiKMS)
	capiChain := mustCertificateWithKey(t, capiKey.PublicKey)
	require.NoError(t, capiKMS.StoreCertificateChain(&apiv1.StoreCertificateChainRequest{
		Name:             platformCertName,
		CertificateChain: capiChain,
	}))
	t.Cleanup(func() {
		assert.NoError(t, capiKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
			Name: platformCertName,
		}))
		assert.NoError(t, capiKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
			Name: uri.New(Scheme, url.Values{
				"issuer": []string{capiChain[1].Issuer.CommonName},
				"serial": []string{capiChain[1].SerialNumber.String()},
			}).String(),
		}))
	})

	type args struct {
		req *apiv1.LoadCertificateRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      *x509.Certificate
		assertion assert.ErrorAssertionFunc
	}{
		{"ok capi", capiKMS, args{&apiv1.LoadCertificateRequest{
			Name: platformCertName,
		}}, capiChain[0], assert.NoError},
		{"ok capi issuer and serial", capiKMS, args{&apiv1.LoadCertificateRequest{
			Name: uri.New(Scheme, url.Values{
				"issuer": []string{capiChain[0].Issuer.CommonName},
				"serial": []string{capiChain[0].SerialNumber.String()},
			}).String(),
		}}, capiChain[0], assert.NoError},
		{"fail capi missing", capiKMS, args{&apiv1.LoadCertificateRequest{
			Name: platformMissingName,
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.LoadCertificate(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKMS_StoreCertificate_capi(t *testing.T) {
	capiKMS := mustCAPIKMS(t)
	capiKey := mustCreatePlatformKey(t, capiKMS)
	capiChain := mustCertificateWithKey(t, capiKey.PublicKey)
	chainNoKey := mustCertificate(t, "")

	type args struct {
		req *apiv1.StoreCertificateRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok capi", capiKMS, args{&apiv1.StoreCertificateRequest{
			Name:        platformCertName,
			Certificate: capiChain[0],
		}}, assert.NoError},
		{"ok capi no key", capiKMS, args{&apiv1.StoreCertificateRequest{
			Name:        platformCertName + "-other",
			Certificate: chainNoKey[0],
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			t.Cleanup(func() {
				assert.NoError(t, capiKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
					Name: platformCertName,
				}))
			})
			return assert.NoError(t, err)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.StoreCertificate(tt.args.req))
		})
	}
}

func TestKMS_LoadCertificateChain_capi(t *testing.T) {
	capiKMS := mustCAPIKMS(t)
	capiKey := mustCreatePlatformKey(t, capiKMS)
	capiChain := mustCertificateWithKey(t, capiKey.PublicKey)
	require.NoError(t, capiKMS.StoreCertificateChain(&apiv1.StoreCertificateChainRequest{
		Name:             platformCertName,
		CertificateChain: capiChain,
	}))
	t.Cleanup(func() {
		assert.NoError(t, capiKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
			Name: platformCertName,
		}))
		assert.NoError(t, capiKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
			Name: uri.New(Scheme, url.Values{
				"issuer": []string{capiChain[1].Issuer.CommonName},
				"serial": []string{capiChain[1].SerialNumber.String()},
			}).String(),
		}))
	})

	type args struct {
		req *apiv1.LoadCertificateChainRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      []*x509.Certificate
		assertion assert.ErrorAssertionFunc
	}{
		{"ok capi", capiKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: platformCertName,
		}}, capiChain, assert.NoError},
		{"ok capi issuer and serial", capiKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: uri.New(Scheme, url.Values{
				"issuer": []string{capiChain[0].Issuer.CommonName},
				"serial": []string{capiChain[0].SerialNumber.String()},
			}).String(),
		}}, capiChain, assert.NoError},
		{"fail capi missing", capiKMS, args{&apiv1.LoadCertificateChainRequest{
			Name: platformMissingName,
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.LoadCertificateChain(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestKMS_StoreCertificateChain_capi(t *testing.T) {
	capiKMS := mustCAPIKMS(t)
	capiKey := mustCreatePlatformKey(t, capiKMS)
	capiChain := mustCertificateWithKey(t, capiKey.PublicKey)
	chainNoKey := mustCertificate(t, "")

	type args struct {
		req *apiv1.StoreCertificateChainRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok capi", capiKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             platformCertName,
			CertificateChain: capiChain,
		}}, assert.NoError},
		{"ok capi no key", capiKMS, args{&apiv1.StoreCertificateChainRequest{
			Name:             platformCertName + "-other",
			CertificateChain: chainNoKey,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			// Storing a certificate with no key is not supported on TPMKMS.
			if capiKMS.Type() == apiv1.TPMKMS {
				return assert.Error(t, err)
			}

			t.Cleanup(func() {
				assert.NoError(t, capiKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
					Name: platformCertName,
				}))

				if capiKMS.Type() == apiv1.MacKMS {
					assert.NoError(t, capiKMS.DeleteCertificate(&apiv1.DeleteCertificateRequest{
						Name: uri.New(Scheme, url.Values{
							"serial": []string{hex.EncodeToString(capiChain[1].SerialNumber.Bytes())},
						}).String(),
					}))
				}
			})
			return assert.NoError(t, err)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.StoreCertificateChain(tt.args.req))
		})
	}
}

func TestKMS_DeleteCertificate_capi(t *testing.T) {
	capiKMS := mustCAPIKMS(t)
	_ = mustCreatePlatformCertificate(t, capiKMS, withNoCleanupCertificate())

	type args struct {
		req *apiv1.DeleteCertificateRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"ok capi", capiKMS, args{&apiv1.DeleteCertificateRequest{
			Name: platformCertName,
		}}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			_, loadErr := capiKMS.LoadCertificate(&apiv1.LoadCertificateRequest{
				Name: platformCertName,
			})
			return assert.NoError(t, err) && assert.Error(t, loadErr)
		}},
		{"fail platform missing", capiKMS, args{&apiv1.DeleteCertificateRequest{
			Name: platformMissingName,
		}}, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, tt.kms.DeleteCertificate(tt.args.req))
		})
	}
}

func TestKMS_SearchKeys_capi(t *testing.T) {
	suffix := mustSuffix(t)
	capiKMS := mustCAPIKMS(t)

	platformKeys := make([]*apiv1.CreateKeyResponse, 4)
	for i := range platformKeys {
		name := fmt.Sprintf("kms:name=search-test-%d-%s", i, suffix)
		platformKeys[i] = mustCreatePlatformKey(t, capiKMS, withName(name))
	}

	type args struct {
		req *apiv1.SearchKeysRequest
	}
	tests := []struct {
		name      string
		kms       *KMS
		args      args
		want      *apiv1.SearchKeysResponse
		assertion assert.ErrorAssertionFunc
	}{
		{"fail capi", capiKMS, args{&apiv1.SearchKeysRequest{
			Query: "kms:",
		}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.kms.SearchKeys(tt.args.req)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_transformToCAPIKMS(t *testing.T) {
	tests := []struct {
		name      string
		rawuri    string
		want      string
		assertion assert.ErrorAssertionFunc
	}{
		{"scheme", "kms:", "capi:skip-find-certificate-key=true", assert.NoError},
		{"with name", "kms:name=foo", "capi:key=foo;skip-find-certificate-key=true", assert.NoError},
		{"with hw", "kms:name=foo;hw=true", "capi:key=foo;provider=Microsoft+Platform+Crypto+Provider;skip-find-certificate-key=true", assert.NoError},
		{"with hw on query", "kms:name=foo?hw=true", "capi:key=foo;provider=Microsoft+Platform+Crypto+Provider;skip-find-certificate-key=true", assert.NoError},
		{"with skip-find-certificate-key", "kms:name=foo;skip-find-certificate-key=false", "capi:key=foo;skip-find-certificate-key=false", assert.NoError},
		{"with provider", "kms:name=foo;hw=true;provider=my", "capi:key=foo;provider=my;skip-find-certificate-key=true", assert.NoError},
		{"with extrasValues", "kms:name=foo;foo=bar?baz=qux", "capi:baz=qux;foo=bar;key=foo;skip-find-certificate-key=true", assert.NoError},
		{"fail parse", "capikms:name=foo", "", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transformToCAPIKMS(tt.rawuri)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_transformFromCAPIKMS(t *testing.T) {
	tests := []struct {
		name      string
		rawuri    string
		want      string
		assertion assert.ErrorAssertionFunc
	}{
		{"scheme", "capi:", "kms:", assert.NoError},
		{"with key", "capi:key=foo", "kms:name=foo", assert.NoError},
		{"with provider", "capi:key=foo;provider=Microsoft+Platform+Crypto+Provider", "kms:hw=true;name=foo;provider=Microsoft+Platform+Crypto+Provider", assert.NoError},
		{"with provider on query", "capi:key=foo?provider=my", "kms:name=foo;provider=my", assert.NoError},
		{"with others", "capi:key=foo;serial=1234;issuer=My+CA", "kms:issuer=My+CA;name=foo;serial=1234", assert.NoError},
		{"fail empty", "", "", assert.Error},
		{"fail scheme", "kms:", "", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transformFromCAPIKMS(tt.rawuri)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
