//go:build tpmsimulator
// +build tpmsimulator

package simulator

import (
	"context"
	"fmt"
	"io"

	gotpm "github.com/google/go-tpm-tools/simulator"
)

type Simulator struct {
	wrapped *gotpm.Simulator
}

func New() *Simulator {
	return &Simulator{}
}

func (s *Simulator) Open(ctx context.Context) error {
	var sim *gotpm.Simulator
	var err error
	if s.wrapped == nil {
		sim, err = gotpm.Get()
		if err != nil {
			return err
		}
	}

	s.wrapped = sim
	return nil
}

func (s *Simulator) Close() error {
	if s.wrapped == nil {
		return nil
	}

	if s.wrapped.IsClosed() {
		return nil
	}

	if err := s.wrapped.Close(); err != nil {
		return fmt.Errorf("failed closing TPM simulator: %w", err)
	}

	s.wrapped = nil

	return nil
}

func (s *Simulator) MeasurementLog() ([]byte, error) {
	return nil, nil
}

func (s *Simulator) Read(p []byte) (n int, err error) {
	return s.wrapped.Read(p)
}

func (s *Simulator) Write(p []byte) (n int, err error) {
	return s.wrapped.Write(p)
}

var _ io.ReadWriteCloser = (*Simulator)(nil)
