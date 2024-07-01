package debug

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_binTapWrites(t *testing.T) {
	var buf bytes.Buffer
	bt := NewBinTap(&buf)
	n, err := bt.Tx().Write([]byte{1, 2, 3, 4})
	require.NoError(t, err)
	require.Equal(t, 4, n)
	n, err = bt.Rx().Write([]byte{5, 6, 7, 8})
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, buf.Bytes())
}
