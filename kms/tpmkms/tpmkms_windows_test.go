//go:build windows

package tpmkms

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/capi"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm"
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
