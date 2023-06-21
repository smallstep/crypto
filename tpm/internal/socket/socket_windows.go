//go:build windows
// +build windows

package socket

import (
	"io"
)

func new(_ string) (io.ReadWriteCloser, error) {
	return nil, errors.New("connecting to a TPM using a UNIX socket is not supported on Windows")
}
