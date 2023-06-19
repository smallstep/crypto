//go:build windows
// +build windows

package close

import (
	"io"
)

func closeRWC(rwc io.ReadWriteCloser) error {
	return rwc.Close()
}
