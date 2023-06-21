//go:build windows
// +build windows

package closer

import (
	"io"

	"github.com/smallstep/go-attestation/attest"
)

func closeRWC(rwc io.ReadWriteCloser) error {
	return rwc.Close()
}

func attestTPM(t *attest.TPM, _ *attest.OpenConfig) error {
	return t.Close()
}
