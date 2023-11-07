//go:build tpmsimulator

package tss2

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/tpm/simulator"
)

func openTPM(t *testing.T) io.ReadWriteCloser {
	t.Helper()

	sim, err := simulator.New()
	require.NoError(t, err)
	require.NoError(t, sim.Open())
	return sim
}
