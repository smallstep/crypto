package rand

import (
	"fmt"
	"io"

	"go.step.sm/crypto/tpm"
)

func New(opts ...tpm.NewTPMOption) (io.Reader, error) {
	t, err := tpm.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed creating TPM instance: %w", err)
	}
	return t.RandomReader()
}
