//go:build cgo
// +build cgo

package tpm

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/tpm/storage"
)

func newSimulatedTPM(t *testing.T) *TPM {
	t.Helper()
	tmpDir := t.TempDir()
	tpm, err := New(withSimulator(t), WithStore(storage.NewDirstore(tmpDir))) // TODO: provide in-memory storage implementation instead
	require.NoError(t, err)
	return tpm
}

func withSimulator(t *testing.T) NewTPMOption {
	t.Helper()
	return func(tpm *TPM) error {
		tpm.enableSimulator = true
		return nil
	}
}
