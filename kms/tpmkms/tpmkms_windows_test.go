//go:build windows

package tpmkms

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/capi"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/randutil"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/storage"
	"go.step.sm/crypto/x509util"
)

func TestNew_windows(t *testing.T) {
	ctx := t.Context()

	km, err := capi.New(ctx, apiv1.Options{
		Type: apiv1.CAPIKMS,
		URI:  uri.New("capi", url.Values{"provider": []string{microsoftPCP}}).String(),
	})
	require.NoError(t, err)

	apiv1.Register(apiv1.CAPIKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return km, nil
	})

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name      string
		args      args
		want      *TPMKMS
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{ctx, apiv1.Options{Type: "tpmkms"}}, &TPMKMS{
			tpm: nil, // not known
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  60,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			}}, assert.NoError},
		{"ok uri", args{ctx, apiv1.Options{Type: "tpmkms", URI: "tpmkms:renewal-percentage=70"}}, &TPMKMS{
			tpm: nil, // not known
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  70,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			}}, assert.NoError},
		{"ok cng", args{ctx, apiv1.Options{Type: "tpmkms", URI: "tpmkms:enable-cng=true"}}, &TPMKMS{
			tpm:                       nil, // not known
			windowsCertificateManager: km,
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  60,
				windowsCNG:                       true,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			}}, assert.NoError},
		{"ok cng stores", args{ctx, apiv1.Options{
			Type: "tpmkms",
			URI:  "tpmkms:enable-cng=true;store=CA;store-location=machine;intermediate-store=My;intermediate-store-location=machine",
		}}, &TPMKMS{
			tpm:                       nil, // not known
			windowsCertificateManager: km,
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  60,
				windowsCNG:                       true,
				windowsCertificateStore:          "CA",
				windowsCertificateStoreLocation:  "machine",
				windowsIntermediateStore:         "My",
				windowsIntermediateStoreLocation: "machine",
			}}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.opts)
			tt.assertion(t, err)
			// It is not possible to compare a *tpm.TPM with the one created by
			// New because the storage.Dirstore contains functions that cannot
			// be compared.
			if got != nil {
				assert.NotNil(t, got.tpm)
				assert.IsType(t, &tpm.TPM{}, got.tpm)
				tt.want.tpm = got.tpm
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewWithTPM_windows(t *testing.T) {
	ctx := t.Context()
	tp, err := tpm.New()
	require.NoError(t, err)

	km, err := capi.New(ctx, apiv1.Options{
		Type: apiv1.CAPIKMS,
		URI:  uri.New("capi", url.Values{"provider": []string{microsoftPCP}}).String(),
	})
	require.NoError(t, err)

	apiv1.Register(apiv1.CAPIKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return km, nil
	})

	type args struct {
		ctx  context.Context
		t    *tpm.TPM
		opts []Option
	}
	tests := []struct {
		name      string
		args      args
		want      *TPMKMS
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{ctx, tp, nil}, &TPMKMS{
			tpm: tp,
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  60,
				windowsCNG:                       false,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			},
		}, assert.NoError},
		{"ok with default stores", args{ctx, tp, []Option{
			WithWindowsCertificateStore("", ""),
			WithWindowsIntermediateStore("", ""),
		}}, &TPMKMS{
			tpm:                       tp,
			windowsCertificateManager: km,
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  60,
				windowsCNG:                       true,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			},
		}, assert.NoError},
		{"ok with custom stores", args{ctx, tp, []Option{
			WithWindowsCertificateStore("CA", "machine"),
			WithWindowsIntermediateStore("My", "machine"),
		}}, &TPMKMS{
			tpm:                       tp,
			windowsCertificateManager: km,
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  60,
				windowsCNG:                       true,
				windowsCertificateStore:          "CA",
				windowsCertificateStoreLocation:  "machine",
				windowsIntermediateStore:         "My",
				windowsIntermediateStoreLocation: "machine",
			},
		}, assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewWithTPM(tt.args.ctx, tt.args.t, tt.args.opts...)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// newPCPCertManager constructs the same kind of CAPIKMS-bound-to-PCP cert
// manager that TPMKMS attaches as its windowsCertificateManager when
// enable-cng=true. Returning the underlying CAPIKMS lets tests reach into
// it directly to set up the Software-KSP fixtures the TPMKMS-side fallback
// is expected to find.
func newPCPCertManager(t *testing.T) apiv1.KeyManager {
	t.Helper()
	km, err := capi.New(t.Context(), apiv1.Options{
		Type: apiv1.CAPIKMS,
		URI:  uri.New("capi", url.Values{"provider": []string{microsoftPCP}}).String(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close() })

	apiv1.Register(apiv1.CAPIKMS, func(context.Context, apiv1.Options) (apiv1.KeyManager, error) {
		return km, nil
	})
	return km
}

// makeSoftwareKSPKeyAndCert mirrors the helper in capi's tests: it creates
// a Software-KSP CNG key in CurrentUser, signs a short-lived cert with it,
// stores the cert in CurrentUser\My, and binds the cert to the key. Used to
// reproduce the unprotected-endpoint configuration the agent emits today.
func makeSoftwareKSPKeyAndCert(t *testing.T, subject string) (containerName string) {
	t.Helper()

	suffix, err := randutil.Hex(8)
	require.NoError(t, err)
	containerName = "step-tpmkms-test-" + suffix

	km, err := capi.New(t.Context(), apiv1.Options{
		Type: apiv1.CAPIKMS,
		URI:  uri.New("capi", url.Values{"provider": []string{capi.ProviderMSKSP}}).String(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close() })

	created, err := km.CreateKey(&apiv1.CreateKeyRequest{
		Name:               uri.New("capi", url.Values{"provider": []string{capi.ProviderMSKSP}, "key": []string{containerName}}).String(),
		SignatureAlgorithm: apiv1.SHA256WithRSA,
		Bits:               2048,
	})
	require.NoError(t, err)

	signer, err := km.CreateSigner(&created.CreateSignerRequest)
	require.NoError(t, err)

	// Populate SubjectKeyId so the SKI-indexed branch in CAPI can find
	// this cert; x509.CreateCertificate doesn't auto-populate it on
	// leaf certs.
	ski, err := x509util.GenerateSubjectKeyID(signer.Public())
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: subject},
		Issuer:       pkix.Name{CommonName: subject},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId: ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	require.NoError(t, km.StoreCertificate(&apiv1.StoreCertificateRequest{
		Name: uri.New("capi", url.Values{
			"store-location": []string{"user"},
			"store":          []string{"My"},
		}).String(),
		Certificate: cert,
	}))

	t.Cleanup(func() {
		// Best-effort: tests that delete via TPMKMS will already have
		// removed the cert; this cleans up the key, and removes the cert
		// if the test didn't delete it itself.
		_ = km.DeleteCertificate(&apiv1.DeleteCertificateRequest{
			Name: uri.New("capi", url.Values{
				"key":            []string{containerName},
				"store-location": []string{"user"},
				"store":          []string{"My"},
			}).String(),
		})
		_ = km.DeleteKey(&apiv1.DeleteKeyRequest{
			Name: uri.New("capi", url.Values{
				"provider": []string{capi.ProviderMSKSP},
				"key":      []string{containerName},
			}).String(),
		})
	})

	return containerName
}

// newTPMKMSForFallback builds a TPMKMS shaped the way the agent's
// reloadsrv wires it on Windows: enable-cng=true, user/My defaults, a
// real TPM with an empty per-test storage directory (so GetPublicKey on
// a Software-KSP container resolves to tpm.ErrNotFound and drives the
// fallback path — without storage the call returns "no storage
// configured", which does NOT satisfy errors.Is(err, NotFoundError{})
// and therefore wouldn't reach the fallback in production), and a
// PCP-bound CAPIKMS as the windowsCertificateManager.
func newTPMKMSForFallback(t *testing.T) *TPMKMS {
	t.Helper()
	tp, err := tpm.New(tpm.WithStore(storage.NewDirstore(t.TempDir())))
	require.NoError(t, err)

	cm := newPCPCertManager(t)
	return &TPMKMS{
		tpm: tp,
		opts: &options{
			windowsCNG:                       true,
			windowsCertificateStore:          "My",
			windowsCertificateStoreLocation:  "user",
			windowsIntermediateStore:         defaultIntermediateStore,
			windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
		},
		windowsCertificateManager: cm.(apiv1.CertificateChainManager),
	}
}

// TestLoadCertificateChain_softwareKSP_fallback exercises the scenario from
// the agent's renewal cleanup: a TPMKMS configured with enable-cng=true is
// asked to load a cert by name, but the name refers to a Software-KSP
// container instead of a TPM key. Pre-fix, TPMKMS.GetPublicKey returned
// NotFoundError and the cert was never found. With the fallback, TPMKMS
// hands the container name to CAPI, which enumerates by KeyProvInfo.
func TestLoadCertificateChain_softwareKSP_fallback(t *testing.T) {
	k := newTPMKMSForFallback(t)

	container := makeSoftwareKSPKeyAndCert(t, "tpmkms-fallback-load")

	chain, err := k.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
		Name: uri.New(Scheme, url.Values{
			"name":           []string{container},
			"store-location": []string{"user"},
			"store":          []string{"My"},
		}).String(),
	})
	require.NoError(t, err)
	require.NotEmpty(t, chain)
	assert.Equal(t, "tpmkms-fallback-load", chain[0].Subject.CommonName)
}

// TestDeleteCertificate_softwareKSP_fallback is the delete-by-name version
// of the load test. This is the call the agent's storeCertificateChain
// wrapper makes in its deferred cleanup; without this path working,
// renewals leak one duplicate per cycle on unprotected endpoints.
func TestDeleteCertificate_softwareKSP_fallback(t *testing.T) {
	k := newTPMKMSForFallback(t)

	container := makeSoftwareKSPKeyAndCert(t, "tpmkms-fallback-delete")

	require.NoError(t, k.DeleteCertificate(&apiv1.DeleteCertificateRequest{
		Name: uri.New(Scheme, url.Values{
			"name":           []string{container},
			"store-location": []string{"user"},
			"store":          []string{"My"},
		}).String(),
	}))

	// Second load must miss — proves the fallback delete actually
	// removed the cert from the store and we don't return the same one
	// repeatedly.
	_, err := k.LoadCertificateChain(&apiv1.LoadCertificateChainRequest{
		Name: uri.New(Scheme, url.Values{
			"name":           []string{container},
			"store-location": []string{"user"},
			"store":          []string{"My"},
		}).String(),
	})
	assert.ErrorIs(t, err, apiv1.NotFoundError{})
}
