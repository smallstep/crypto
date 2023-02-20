//go:build cgo
// +build cgo

package tpm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTPM_GetEKs(t *testing.T) {
	tpm := newSimulatedTPM(t)
	eks, err := tpm.GetEKs(context.Background())
	require.NoError(t, err)
	require.Len(t, eks, 1)
}
