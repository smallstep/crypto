package socket

import (
	"errors"
	"io"
)

var (
	ErrNotAvailable = errors.New("socket not available")
	ErrNotSupported = errors.New("connecting to a TPM using a UNIX socket is not supported on Windows")
)

func New(path string) (io.ReadWriteCloser, error) {
	return newSocket(path)
}

type CommandChannelWithoutMeasurementLog struct {
	io.ReadWriteCloser
}

func (c *CommandChannelWithoutMeasurementLog) MeasurementLog() ([]byte, error) {
	return nil, nil
}
