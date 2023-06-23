//go:build tpmsimulator
// +build tpmsimulator

package rand

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/tpm"
	"go.step.sm/crypto/tpm/simulator"
)

func withSimulator(t *testing.T) tpm.NewTPMOption {
	t.Helper()
	var sim simulator.Simulator
	t.Cleanup(func() {
		if sim == nil {
			return
		}
		err := sim.Close()
		require.NoError(t, err)
	})
	sim = simulator.New()
	err := sim.Open()
	require.NoError(t, err)
	return tpm.WithSimulator(sim)
}

func TestNew(t *testing.T) {
	r, err := New(withSimulator(t))
	require.NoError(t, err)
	require.NotNil(t, r)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), r)
	require.NoError(t, err)
	if assert.NotNil(t, ecdsaKey) {
		size := (ecdsaKey.D.BitLen() + 7) / 8
		require.Equal(t, 32, size)
	}

	rsaKey, err := rsa.GenerateKey(r, 2048)
	require.NoError(t, err)
	if assert.NotNil(t, rsaKey) {
		require.Equal(t, 256, rsaKey.Size()) // 2048 bits; 256 bytes expected to have been read
	}
}
