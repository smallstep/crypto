package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlackHoleContext(t *testing.T) {
	t.Parallel()

	got := BlackHoleContext(nil) //nolint:staticcheck // nil context for testing
	require.NotNil(t, got)
	require.NotNil(t, FromContext(got))

	got = BlackHoleContext(context.TODO())
	require.NotNil(t, got)
	require.NotNil(t, FromContext(got))
}
