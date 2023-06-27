//go:build windows
// +build windows

package open

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

func open(_ string) (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
