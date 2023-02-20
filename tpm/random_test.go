//go:build cgo
// +build cgo

package tpm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTPM_GenerateRandom(t *testing.T) {
	tpm := newSimulatedTPM(t)
	b, err := tpm.GenerateRandom(context.Background(), 16)
	require.NoError(t, err)
	require.Len(t, b, 16)

	b, err = tpm.GenerateRandom(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, b, 10)
}
