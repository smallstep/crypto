//go:build tpmsimulator
// +build tpmsimulator

package tpm

import (
	"context"
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

func TestTPM_GenerateRandom(t *testing.T) {
	tpm := newSimulatedTPM(t)
	b, err := tpm.GenerateRandom(context.Background(), 16)
	require.NoError(t, err)
	require.Len(t, b, 16)

	b, err = tpm.GenerateRandom(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, b, 10)
}

func TestTPM_GetEKs(t *testing.T) {
	tpm := newSimulatedTPM(t)
	eks, err := tpm.GetEKs(context.Background())
	require.NoError(t, err)
	require.Len(t, eks, 1)
}
