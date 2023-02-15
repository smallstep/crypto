package tpm

import (
	"context"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"go.step.sm/crypto/tpm/internal/open"
)

func (t *TPM) GenerateRandom(ctx context.Context, size uint16) ([]byte, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	rwc, err := open.TPM(t.deviceName)
	if err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer rwc.Close()

	r, err := tpm2.GetRandom(rwc, size)
	if err != nil {
		return nil, fmt.Errorf("failed generating random data: %w", err)
	}

	return r, nil
}
