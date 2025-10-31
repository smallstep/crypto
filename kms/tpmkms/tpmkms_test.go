package tpmkms

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/tss2"
)

func TestNew(t *testing.T) {
	type args struct {
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *TPMKMS
		wantErr bool
	}{
		{"ok/defaults", args{apiv1.Options{Type: "tpmkms"}}, &TPMKMS{
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  60,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			}}, false},
		{"ok/uri", args{apiv1.Options{Type: "tpmkms", URI: "tpmkms:device=/dev/tpm0;storage-directory=/tmp/tpmstorage;renewal-percentage=70"}}, &TPMKMS{
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  70,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			}}, false},
		{"ok/disable-early-renewal", args{apiv1.Options{Type: "tpmkms", URI: "tpmkms:disable-early-renewal=true"}}, &TPMKMS{
			opts: &options{
				identityEarlyRenewalEnabled:      false,
				identityRenewalPeriodPercentage:  0,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			}}, false},
		{"fail/uri-scheme", args{apiv1.Options{Type: "tpmkms", URI: "tpmkmz://device=/dev/tpm0"}}, &TPMKMS{}, true},
		{"fail/renewal-percentage-too-low", args{apiv1.Options{Type: "tpmkms", URI: "tpmkms:renewal-percentage=0"}}, &TPMKMS{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(context.Background(), tt.args.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			if assert.NotNil(t, got) {
				assert.NotNil(t, got.tpm)
				assert.Equal(t, tt.want.opts, got.opts)
			}
		})
	}
}

func TestNew_no_windows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("This test cannot run on windows")
	}

	got, err := New(t.Context(), apiv1.Options{
		URI: "tpmkms:enable-cng=true",
	})
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestNewWithTPM(t *testing.T) {
	ctx := t.Context()
	tp, err := tpm.New()
	require.NoError(t, err)

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
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			},
		}, assert.NoError},
		{"ok without early renewal", args{ctx, tp, []Option{WithDisableIdentityEarlyRenewal()}}, &TPMKMS{
			tpm: tp,
			opts: &options{
				identityEarlyRenewalEnabled:      false,
				identityRenewalPeriodPercentage:  0,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			},
		}, assert.NoError},
		{"ok with other options", args{ctx, tp, []Option{
			WithIdentityEarlyRenewalPercentage(70),
			WithAttestationCA("https://ca.example.com", "path/to/file.crt", true),
		}}, &TPMKMS{
			tpm: tp,
			opts: &options{
				identityEarlyRenewalEnabled:      true,
				identityRenewalPeriodPercentage:  70,
				attestationCABaseURL:             "https://ca.example.com",
				attestationCARootFile:            "path/to/file.crt",
				attestationCAInsecure:            true,
				windowsCertificateStore:          defaultStore,
				windowsCertificateStoreLocation:  defaultStoreLocation,
				windowsIntermediateStore:         defaultIntermediateStore,
				windowsIntermediateStoreLocation: defaultIntermediateStoreLocation,
			},
		}, assert.NoError},
		{"fail percentage 0", args{ctx, tp, []Option{WithIdentityEarlyRenewalPercentage(0)}}, nil, assert.Error},
		{"fail percentage 101", args{ctx, tp, []Option{WithIdentityEarlyRenewalPercentage(101)}}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewWithTPM(tt.args.ctx, tt.args.t, tt.args.opts...)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_parseTSS2(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/ec-tss2.pem")
	require.NoError(t, err)

	type args struct {
		pemBytes []byte
	}
	tests := []struct {
		name      string
		args      args
		want      *tss2.TPMKey
		assertion assert.ErrorAssertionFunc
	}{
		{"ok", args{pemBytes}, &tss2.TPMKey{
			Type:      asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3},
			EmptyAuth: true,
			Parent:    0x40000001,
			PublicKey: []byte{
				0x00, 0x58,
				0x00, 0x23, 0x00, 0x0b, 0x00, 0x04, 0x00, 0x72,
				0x00, 0x00, 0x00, 0x10, 0x00, 0x18, 0x00, 0x0b,
				0x00, 0x03, 0x00, 0x10, 0x00, 0x20, 0x79, 0xb2,
				0xe7, 0x1a, 0x50, 0xc0, 0x37, 0x96, 0x87, 0x76,
				0x47, 0xdf, 0x45, 0x3a, 0x81, 0x76, 0xc4, 0x0d,
				0x9c, 0xee, 0xb4, 0x69, 0x8f, 0x97, 0xbe, 0x0e,
				0x6e, 0xf3, 0x4b, 0x08, 0x6a, 0xe3, 0x00, 0x20,
				0xcd, 0x04, 0xdf, 0x39, 0xdd, 0xa7, 0x9d, 0xfd,
				0xd9, 0x33, 0xc1, 0xae, 0x82, 0xb3, 0x3c, 0xb1,
				0xc4, 0xc0, 0xb8, 0x94, 0x55, 0xe0, 0x66, 0x3a,
				0x10, 0x46, 0xde, 0x4b, 0x2c, 0xfe, 0xe2, 0x02,
			},
			PrivateKey: []byte{
				0x00, 0x7e,
				0x00, 0x20, 0x83, 0x0e, 0xdf, 0x6d, 0x93, 0x15,
				0x89, 0xdd, 0x31, 0xa9, 0xe1, 0xa6, 0xf4, 0xe0,
				0x2c, 0xc8, 0x85, 0x77, 0xa5, 0x6c, 0xdc, 0x75,
				0x6c, 0x3a, 0xb1, 0xdb, 0xd7, 0x9a, 0x8b, 0x65,
				0x30, 0xd0, 0x00, 0x10, 0x4c, 0x70, 0x5f, 0x8b,
				0xdc, 0x2d, 0xb7, 0xdb, 0x61, 0x54, 0xd3, 0xad,
				0x03, 0x1d, 0x7b, 0xf9, 0xe9, 0x4a, 0xbc, 0xee,
				0xe3, 0x2e, 0xfe, 0xa5, 0x84, 0xdc, 0x75, 0x3e,
				0xaf, 0x9f, 0x39, 0xeb, 0xee, 0xf4, 0x3f, 0xde,
				0x08, 0xd3, 0x3d, 0xcf, 0x97, 0x1c, 0x25, 0x9f,
				0x68, 0x86, 0x86, 0x16, 0xca, 0x67, 0xc8, 0x10,
				0x40, 0xd2, 0xa1, 0x88, 0xe7, 0x44, 0xe0, 0xc6,
				0x03, 0x3e, 0x73, 0x75, 0xba, 0xab, 0xdc, 0xc0,
				0x9c, 0x1d, 0xec, 0xd6, 0x75, 0x7e, 0xa9, 0xf0,
				0x04, 0xa9, 0x2c, 0xe8, 0x4d, 0x6f, 0x81, 0x29,
				0xde, 0xb5, 0x87, 0x8d, 0xa2, 0x84,
			},
		}, assert.NoError},
		{"fail empty", args{nil}, nil, assert.Error},
		{"fail no pem", args{[]byte("not a pem")}, nil, assert.Error},
		{"fail type", args{[]byte("-----BEGIN FOO-----\nMCgGBmeBBQoBA6ADAQH/AgRAAAABBAgABnB1YmxpYwQJAAdwcml2YXRl\n-----END FOO-----")}, nil, assert.Error},
		{"fail parse", args{[]byte("-----BEGIN TSS2 PRIVATE KEY-----\nbm90LWEta2V5Cg==\n-----END TSS2 PRIVATE KEY-----")}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTSS2(tt.args.pemBytes)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_notFoundError(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name      string
		args      args
		assertion assert.ErrorAssertionFunc
	}{
		{"nil", args{nil}, assert.NoError},
		{"tpm not found", args{tpm.ErrNotFound}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.ErrorIs(t, err, apiv1.NotFoundError{}, i...)
		}},
		{"tpm not found wrapped", args{fmt.Errorf("some error: %w", tpm.ErrNotFound)}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.ErrorIs(t, err, apiv1.NotFoundError{}, i...)
		}},
		{"other", args{tpm.ErrExists}, func(tt assert.TestingT, err error, i ...interface{}) bool {
			return assert.False(t, errors.Is(err, apiv1.NotFoundError{}), i...)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assertion(t, notFoundError(tt.args.err))
		})
	}
}

func Test_SetPreferredSignatureAlgorithms(t *testing.T) {
	old := preferredSignatureAlgorithms
	want := []apiv1.SignatureAlgorithm{
		apiv1.ECDSAWithSHA256,
	}
	SetPreferredSignatureAlgorithms(want)
	assert.Equal(t, preferredSignatureAlgorithms, want)
	SetPreferredSignatureAlgorithms(old)
}

func Test_PreferredSignatureAlgorithms(t *testing.T) {
	assert.Equal(t, PreferredSignatureAlgorithms(), preferredSignatureAlgorithms)
}
