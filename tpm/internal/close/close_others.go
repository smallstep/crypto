//go:build !windows
// +build !windows

package closer

import (
	"io"

	"github.com/google/go-tpm/tpmutil"
	"github.com/smallstep/go-attestation/attest"

	"go.step.sm/crypto/tpm/internal/interceptor"
	"go.step.sm/crypto/tpm/internal/socket"
)

func closeRWC(rwc io.ReadWriteCloser) error {
	if ic, ok := rwc.(*interceptor.RWC); ok {
		rwc = ic.Unwrap()
	}
	if _, ok := rwc.(*tpmutil.EmulatorReadWriteCloser); ok {
		return nil // EmulatorReadWriteCloser automatically closes on every write/read cycle
	}
	return rwc.Close()
}

func attestTPM(t *attest.TPM, c *attest.OpenConfig) error {
	cc := c.CommandChannel
	if ic, ok := cc.(*interceptor.CommandChannel); ok {
		//cc = ic.Unwrap()
		_ = ic
	}
	if _, ok := cc.(*socket.CommandChannelWithoutMeasurementLog); ok {
		return nil // backed by tpmutil.EmulatorReadWriteCloser; already closed
	}

	return t.Close()
}
