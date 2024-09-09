package tpm

import (
	"context"
	"fmt"
	"slices"

	"github.com/google/go-tpm/legacy/tpm2"
	"go.step.sm/crypto/tpm/algorithm"
)

// Capabilities represents the capabilities of the TPM.
type Capabilities struct {
	Algorithms []algorithm.Algorithm
}

// SupportsAlgorithm return whether the provided algorithm
// is supported by the TPM
func (c *Capabilities) SupportsAlgorithm(alg algorithm.Algorithm) bool {
	return slices.Contains(c.Algorithms, alg)
}

// SupportsAlgorithms return whether all algorithms in the provided
// slice are supported by the TPM
func (c *Capabilities) SupportsAlgorithms(algs []algorithm.Algorithm) bool {
	for _, alg := range algs {
		if !c.SupportsAlgorithm(alg) {
			return false
		}
	}
	return true
}

// GetCapabilities returns the capabilities of the TPM; currently suports
// enumerating the supported algorithms
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (t *TPM) GetCapabilities(ctx context.Context) (caps *Capabilities, err error) {
	if t.caps != nil {
		return t.caps, nil
	}

	if err = t.open(goTPMCall(ctx)); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	current := tpm2.AlgUnknown // 0x0000, first property
	caps = &Capabilities{}

	for {
		var (
			data []any
			more bool
		)

		data, more, err := tpm2.GetCapability(t.rwc, tpm2.CapabilityAlgs, 1, uint32(current))
		if err != nil {
			return nil, fmt.Errorf("error getting algorithms capability: %w", err)
		}

		if d, ok := data[0].(tpm2.AlgorithmDescription); ok {
			alg := algorithm.Algorithm(d.ID)
			if !slices.Contains(caps.Algorithms, alg) {
				caps.Algorithms = append(caps.Algorithms, alg)
			}
		}

		if !more {
			break
		}

		current++
	}

	t.caps = caps

	return
}
