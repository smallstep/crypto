//go:build !tpmsimulator
// +build !tpmsimulator

package simulator

import (
	"errors"
	"io"
)

type NoSimulator struct {
}

func New() (Simulator, error) {
	return &NoSimulator{}, errors.New("no simulator available")
}

func (s *NoSimulator) Open() error {
	return errors.New("cannot open: no simulator available")
}

func (s *NoSimulator) Close() error {
	return errors.New("cannot close: no simulator available")
}

func (s *NoSimulator) MeasurementLog() ([]byte, error) {
	return nil, errors.New("cannot get measurement log: no simulator available")
}

func (s *NoSimulator) Read([]byte) (int, error) {
	return -1, errors.New("cannot read: no simulator available")
}

func (s *NoSimulator) Write([]byte) (int, error) {
	return -1, errors.New("cannot write: no simulator available")
}

var _ Simulator = (*NoSimulator)(nil)
var _ io.ReadWriteCloser = (*NoSimulator)(nil)
