//go:build !windows
// +build !windows

package open

import (
	"io"

	"github.com/google/go-tpm/tpm2"
)

func open(deviceName string) (io.ReadWriteCloser, error) {
	if deviceName == "" {
		return tpm2.OpenTPM()
	}

	return tpm2.OpenTPM(deviceName)
}
