//go:build !tpmsimulator
// +build !tpmsimulator

package simulator

import (
	"context"
	"errors"
	"io"
)

type Simulator struct {
}

func New() *Simulator {
	return &Simulator{}
}

func (s *Simulator) Open(ctx context.Context) error {
	return errors.New("no simulator available")
}

func (s *Simulator) Close() error {
	return errors.New("cannot close: no simulator available")
}

func (s *Simulator) MeasurementLog() ([]byte, error) {
	return nil, errors.New("cannot get measurement log: no simulator available")
}

func (s *Simulator) Read(p []byte) (n int, err error) {
	return 0, errors.New("cannot read: no simulator available")
}

func (s *Simulator) Write(p []byte) (n int, err error) {
	return 0, errors.New("cannot write: no simulator available")
}

var _ io.ReadWriteCloser = (*Simulator)(nil)
