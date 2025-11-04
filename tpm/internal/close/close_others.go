//go:build !windows

package closer

import (
	"io"

	"github.com/google/go-tpm/tpmutil"
	"github.com/smallstep/go-attestation/attest"

	"go.step.sm/crypto/tpm/internal/socket"
)

func closeRWC(rwc io.ReadWriteCloser) error {
	if _, ok := rwc.(*tpmutil.EmulatorReadWriteCloser); ok {
		return nil // EmulatorReadWriteCloser automatically closes on every write/read cycle
	}
	return rwc.Close()
}

func attestTPM(t *attest.TPM, c *attest.OpenConfig) error {
	if _, ok := c.CommandChannel.(*socket.CommandChannelWithoutMeasurementLog); ok {
		return nil // backed by tpmutil.EmulatorReadWriteCloser; already closed
	}
	return t.Close()
}
