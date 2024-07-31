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

func TestBlackHole(t *testing.T) {
	t.Parallel()

	store := BlackHole()
	err := store.AddAK(&AK{Name: "ak"})
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	k, err := store.GetAK("ak")
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Nil(t, k)

	err = store.UpdateAK(k)
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	names := store.ListAKNames()
	require.Empty(t, names)

	aks, err := store.ListAKs()
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Empty(t, aks)

	err = store.DeleteAK("ak")
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	err = store.Persist()
	require.NoError(t, err)

	err = store.Load()
	require.NoError(t, err)
}
