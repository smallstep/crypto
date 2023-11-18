//go:build tpmsimulator

package tss2

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/tpm/simulator"
)

var seed string

func init() {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	seed = hex.EncodeToString(b)
}

func openTPM(t *testing.T) io.ReadWriteCloser {
	t.Helper()

	sim, err := simulator.New(simulator.WithSeed(seed))
	require.NoError(t, err)
	require.NoError(t, sim.Open())
	return sim
}
