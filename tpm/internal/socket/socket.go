package socket

import (
	"io"
)

func New(path string) (io.ReadWriteCloser, error) {
	return new(path)
}

type CommandChannelWithoutMeasurementLog struct {
	io.ReadWriteCloser
}

func (c *CommandChannelWithoutMeasurementLog) MeasurementLog() ([]byte, error) {
	return nil, nil
}
