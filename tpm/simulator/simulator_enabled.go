//go:build tpmsimulator
// +build tpmsimulator

package simulator

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	gotpm "github.com/google/go-tpm-tools/simulator"
)

type WrappingSimulator struct {
	wrapped *gotpm.Simulator
	seed    *int64
}

type NewSimulatorOption func(ws *WrappingSimulator) error

func WithSeed(seed string) NewSimulatorOption {
	return func(ws *WrappingSimulator) error {
		b, err := hex.DecodeString(seed)
		if err != nil {
			return fmt.Errorf("failed decoding %q: %w", seed, err)
		}
		if len(b) != 8 {
			return fmt.Errorf("%q has wrong number of bytes (%d)", seed, len(b))
		}
		var intSeed int64
		buf := bytes.NewBuffer(b)
		if err := binary.Read(buf, binary.BigEndian, &intSeed); err != nil {
			return fmt.Errorf("failed reading %q into int64: %w", seed, err)
		}
		ws.seed = &intSeed
		return nil
	}
}

func New(opts ...NewSimulatorOption) (Simulator, error) {
	ws := &WrappingSimulator{}
	for _, applyTo := range opts {
		if err := applyTo(ws); err != nil {
			return nil, fmt.Errorf("failed initializing TPM simulator: %w", err)
		}
	}
	return ws, nil
}

func (s *WrappingSimulator) Open() error {
	var sim *gotpm.Simulator
	var err error
	if s.wrapped == nil {
		if s.seed == nil {
			sim, err = gotpm.Get()
		} else {
			sim, err = gotpm.GetWithFixedSeedInsecure(*s.seed)
		}
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
