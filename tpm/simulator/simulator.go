package simulator

import "io"

type Simulator interface {
	io.ReadWriteCloser
	Open() error
	MeasurementLog() ([]byte, error)
}
