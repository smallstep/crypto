package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
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

func TestBlackHoleListKeys(t *testing.T) {
	got, err := BlackHole().ListKeys()
	assert.NoError(t, err)
	assert.Empty(t, got)
}

func TestBlackHoleListKeyNames(t *testing.T) {
	assert.Empty(t, BlackHole().ListKeyNames())
}

func TestBlackHoleGetKey(t *testing.T) {
	got, err := BlackHole().GetKey("some-key")
	assert.ErrorIs(t, err, ErrNotFound)
	assert.Nil(t, got)
}

func TestBlackHoleAddKey(t *testing.T) {
	assert.ErrorIs(t, BlackHole().AddKey(&Key{}), errBlackHole)
}

func TestBlackHoleUpdateKey(t *testing.T) {
	assert.ErrorIs(t, BlackHole().UpdateKey(&Key{}), errBlackHole)
}

func TestBlackHoleDeleteKey(t *testing.T) {
	assert.ErrorIs(t, BlackHole().DeleteKey("some-key"), ErrNotFound)
}

func TestBlackHoleListAKs(t *testing.T) {
	got, err := BlackHole().ListAKs()
	assert.NoError(t, err)
	assert.Empty(t, got)
}

func TestBlackHoleListAKNames(t *testing.T) {
	got := BlackHole().ListAKNames()
	assert.Empty(t, got)
}

func TestBlackHoleGetAK(t *testing.T) {
	got, err := BlackHole().GetAK("some-ak")
	assert.ErrorIs(t, err, ErrNotFound)
	assert.Nil(t, got)
}

func TestBlackHoleAddAK(t *testing.T) {
	assert.ErrorIs(t, BlackHole().AddAK(&AK{}), errBlackHole)
}

func TestBlackHoleUpdateAK(t *testing.T) {
	assert.ErrorIs(t, BlackHole().UpdateAK(&AK{}), errBlackHole)
}

func TestBlackHoleDeleteAK(t *testing.T) {
	assert.ErrorIs(t, BlackHole().DeleteAK("some-key"), ErrNotFound)
}

func TestBlackHolePersist(t *testing.T) {
	assert.ErrorIs(t, BlackHole().Persist(), errBlackHole)
}

func TestBlackHoleLoad(t *testing.T) {
	assert.NoError(t, BlackHole().Load())
}
