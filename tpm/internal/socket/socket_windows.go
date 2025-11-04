//go:build windows

package socket

import (
	"io"
)

func newSocket(_ string) (io.ReadWriteCloser, error) {
	return nil, ErrNotSupported
}
