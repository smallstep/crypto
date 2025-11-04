//go:build !windows

package tpmkms

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/tpm"
)

func TestNew_no_windows(t *testing.T) {
	got, err := New(t.Context(), apiv1.Options{
		URI: "tpmkms:enable-cng=true",
	})
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestNewWithTPM_no_windows(t *testing.T) {
	tp, err := tpm.New()
	require.NoError(t, err)

	got, err := NewWithTPM(t.Context(), tp, WithWindowsCertificateStore("", ""))
	assert.Error(t, err)
	assert.Nil(t, got)

	got, err = NewWithTPM(t.Context(), tp, WithWindowsIntermediateStore("", ""))
	assert.Error(t, err)
	assert.Nil(t, got)
}
