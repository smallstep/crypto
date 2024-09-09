package tpm

import (
	"testing"

	"github.com/smallstep/assert"
	"go.step.sm/crypto/tpm/algorithm"
)

func Test_Capabilities_SupportsAlgorithms(t *testing.T) {
	caps := &Capabilities{}
	assert.False(t, caps.SupportsAlgorithms(algorithm.AlgorithmRSA))

	caps = &Capabilities{
		Algorithms: []algorithm.Algorithm{algorithm.AlgorithmRSA},
	}
	assert.True(t, caps.SupportsAlgorithms(algorithm.AlgorithmRSA))
}
