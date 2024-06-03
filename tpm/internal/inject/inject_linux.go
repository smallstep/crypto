//go:build linux
// +build linux

package inject

import (
	"io"

	"github.com/smallstep/go-attestation/attest"
)

func Inject(rwc io.ReadWriteCloser) *attest.TPM {
	return attest.InjectSimulatedTPMForTest(rwc)
}
