package open

import (
	"io"
)

func TPM(deviceName string) (io.ReadWriteCloser, error) {
	return open(deviceName)
}
