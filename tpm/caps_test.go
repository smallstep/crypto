package tpm

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.step.sm/crypto/tpm/algorithm"
)

func Test_Capabilities_SupportsAlgorithm(t *testing.T) {
	caps := &Capabilities{}
	assert.False(t, caps.SupportsAlgorithm(algorithm.AlgorithmRSA))

	caps = &Capabilities{
		Algorithms: []algorithm.Algorithm{algorithm.AlgorithmRSA},
	}
	assert.True(t, caps.SupportsAlgorithm(algorithm.AlgorithmRSA))
}

func Test_Capabilities_SupportsAlgorithms(t *testing.T) {
	caps := &Capabilities{}
	assert.False(t, caps.SupportsAlgorithms([]algorithm.Algorithm{algorithm.AlgorithmRSA}))

	caps = &Capabilities{
		Algorithms: []algorithm.Algorithm{algorithm.AlgorithmRSA},
	}
	assert.True(t, caps.SupportsAlgorithms([]algorithm.Algorithm{algorithm.AlgorithmRSA}))
}
