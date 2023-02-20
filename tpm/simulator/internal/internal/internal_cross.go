//go:build !cgo
// +build !cgo

//nolint:gocritic // copied package from github.com/google/go-tpm-tools/simulator/internal
package internal

import (
	"errors"
	"io"
)

// SetSeeds does nothing
func SetSeeds(r io.Reader) {}

// Reset does nothing
func Reset(forceManufacture bool) {}

// RunCommand always returns an error, as we need CGO to use the simulator.
func RunCommand(cmd []byte) ([]byte, error) {
	return nil, errors.New("using the simulator requires building with CGO")
}
