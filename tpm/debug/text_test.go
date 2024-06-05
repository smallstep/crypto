package debug

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_directionalWrapper_Write(t *testing.T) {
	var reads bytes.Buffer
	var writes bytes.Buffer
	tt := NewTextTap(&reads, &writes)
	n, err := tt.Tx().Write([]byte{1, 2, 3, 4})
	require.NoError(t, err)
	require.Equal(t, 12, n)
	require.Equal(t, "-> 01020304\n", writes.String())

	n, err = tt.Rx().Write([]byte{5, 6, 7, 8})
	require.NoError(t, err)
	require.Equal(t, 12, n)
	require.Equal(t, "<- 05060708\n", reads.String())
}
