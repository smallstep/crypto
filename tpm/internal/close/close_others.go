//go:build !windows
// +build !windows

package close

import (
	"io"

	"github.com/google/go-tpm/tpmutil"
)

func closeRWC(rwc io.ReadWriteCloser) error {
	if _, ok := rwc.(*tpmutil.EmulatorReadWriteCloser); ok {
		return nil // EmulatorReadWriteCloser automatically closes on every write/read cycle
	}
	return rwc.Close()
}
