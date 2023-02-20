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
	return nil
}

func (s *Simulator) MeasurementLog() ([]byte, error) {
	return nil, nil
}

func (s *Simulator) Read(p []byte) (n int, err error) {
	return 0, errors.New("can't read")
}

func (s *Simulator) Write(p []byte) (n int, err error) {
	return 0, errors.New("can't write")
}

var _ io.ReadWriteCloser = (*Simulator)(nil)
