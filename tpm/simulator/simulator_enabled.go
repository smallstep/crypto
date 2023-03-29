//go:build tpmsimulator
// +build tpmsimulator

package simulator

import (
	"fmt"
	"io"

	gotpm "github.com/google/go-tpm-tools/simulator"
)

type WrappingSimulator struct {
	wrapped *gotpm.Simulator
}

func New() Simulator {
	return &WrappingSimulator{}
}

func (s *WrappingSimulator) Open() error {
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

func (s *WrappingSimulator) Close() error {
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

func (s *WrappingSimulator) MeasurementLog() ([]byte, error) {
	return nil, nil
}

func (s *WrappingSimulator) Read(p []byte) (int, error) {
	return s.wrapped.Read(p)
}

func (s *WrappingSimulator) Write(p []byte) (int, error) {
	return s.wrapped.Write(p)
}

var _ io.ReadWriteCloser = (*WrappingSimulator)(nil)
