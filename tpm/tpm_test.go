package tpm

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_processName(t *testing.T) {

	name := "name1"
	name, err := processName(name)
	require.NoError(t, err)
	require.Equal(t, "name1", name)

	name, err = processName("")
	require.NoError(t, err)
	require.Len(t, name, 10)
}
