//go:build tpm

package tss2

import (
	"io"
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

func openTPM(t *testing.T) io.ReadWriteCloser {
	t.Helper()

	rwc, err := tpm2.OpenTPM()
	require.NoError(t, err)
	return rwc
}
