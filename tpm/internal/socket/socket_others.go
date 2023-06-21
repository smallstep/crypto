//go:build !windows
// +build !windows

package socket

import (
	"io"
	"os"

	"github.com/google/go-tpm/tpmutil"
)

func new(path string) (io.ReadWriteCloser, error) {
	fi, err := os.Stat(path)
	if err != nil { // TODO(hs): handle specific errors here?
		return nil, err
	}

	if fi.Mode()&os.ModeSocket != 0 {
		return tpmutil.NewEmulatorReadWriteCloser(path), nil
	}

	return nil, nil
}
