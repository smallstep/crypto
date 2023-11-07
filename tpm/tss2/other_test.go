//go:build !tpm && !tpmsimulator

package tss2

import (
	"io"
	"testing"
)

func openTPM(t *testing.T) io.ReadWriteCloser {
	t.Helper()
	t.Skip("Use tags tpm or tpmsimulator")
	return nil
}
