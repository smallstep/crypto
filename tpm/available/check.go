package available

import (
	"fmt"

	"go.step.sm/crypto/tpm"
)

func Check(opts ...tpm.NewTPMOption) error {
	t, err := tpm.New(opts...)
	if err != nil {
		return fmt.Errorf("failed creating TPM instance: %w", err)
	}
	return t.Available()
}
