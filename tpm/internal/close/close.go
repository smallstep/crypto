package closer

import (
	"io"

	"github.com/smallstep/go-attestation/attest"
)

func RWC(rwc io.ReadWriteCloser) error {
	return closeRWC(rwc)
}

func AttestTPM(t *attest.TPM, c *attest.OpenConfig) error {
	return attestTPM(t, c)
}
