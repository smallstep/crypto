package open

import (
	"fmt"
	"io"
	"strings"

	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/tpm/internal/mssim"
)

func TPM(deviceName string) (io.ReadWriteCloser, error) {
	if strings.HasPrefix(deviceName, "mssim:") {
		u, err := uri.ParseWithScheme("mssim", deviceName)
		if err != nil {
			return nil, fmt.Errorf("failed parsing %q: %w", deviceName, err)
		}
		rwc, err := mssim.New(u)
		if err != nil {
			return nil, err
		}
		return rwc, nil
	}

	return open(deviceName)
}
