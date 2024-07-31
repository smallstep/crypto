package storage

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFeedthroughStore_NilKeyOperations(t *testing.T) {
	t.Parallel()

	store := NewFeedthroughStore(nil)

	key1 := &Key{Name: "1st-key"}
	key2 := &Key{Name: "2nd-key"}

	err := store.AddKey(key1)
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	err = store.AddKey(key2)
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	err = store.AddKey(&Key{Name: "1st-key"})
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	k, err := store.GetKey("1st-key")
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Nil(t, k)

	err = store.UpdateKey(k)
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	k, err = store.GetKey("3rd-key")
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Nil(t, k)

	names := store.ListKeyNames()
	require.Empty(t, names)

	keys, err := store.ListKeys()
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Empty(t, keys)

	err = store.DeleteKey("3rd-key")
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	err = store.DeleteKey("1st-key")
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	keys, err = store.ListKeys()
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Empty(t, keys)

	err = store.Persist()
	require.NoError(t, err)

	err = store.Load()
	require.NoError(t, err)
}

func TestFeedthroughStore_KeyOperations(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := NewFeedthroughStore(NewDirstore(tempDir))

	key1 := &Key{Name: "1st-key"}
	key2 := &Key{Name: "2nd-key"}

	err := store.AddKey(key1)
	require.NoError(t, err)

	err = store.AddKey(key2)
	require.NoError(t, err)

	err = store.AddKey(&Key{Name: "1st-key"})
	require.EqualError(t, err, "already exists")

	k, err := store.GetKey("1st-key")
	require.NoError(t, err)
	require.Equal(t, key1, k)

	k.AttestedBy = "ak1"
	err = store.UpdateKey(k)
	require.NoError(t, err)

	k.AttestedBy = ""
	err = store.UpdateKey(k)
	require.NoError(t, err)

	k, err = store.GetKey("3rd-key")
	require.EqualError(t, err, "not found")
	require.Nil(t, k)

	names := store.ListKeyNames()
	require.Equal(t, []string{"1st-key", "2nd-key"}, names)

	keys, err := store.ListKeys()
	require.NoError(t, err)
	require.ElementsMatch(t, []*Key{key1, key2}, keys)

	err = store.DeleteKey("3rd-key")
	require.EqualError(t, err, "not found")

	err = store.DeleteKey("1st-key")
	require.NoError(t, err)

	keys, err = store.ListKeys()
	require.NoError(t, err)
	require.ElementsMatch(t, []*Key{key2}, keys)

	err = store.Persist()
	require.NoError(t, err)

	err = store.Load()
	require.NoError(t, err)
}

func TestFeedthroughStore_NilAKOperations(t *testing.T) {
	t.Parallel()

	store := NewFeedthroughStore(nil)

	ak1 := &AK{Name: "1st-ak"}
	ak2 := &AK{Name: "2nd-ak"}

	err := store.AddAK(ak1)
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	err = store.AddAK(ak2)
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	err = store.AddAK(&AK{Name: "1st-ak"})
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	k, err := store.GetAK("1st-ak")
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Nil(t, k)

	err = store.UpdateAK(k)
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	k, err = store.GetAK("3rd-ak")
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Nil(t, k)

	names := store.ListAKNames()
	require.Empty(t, names)

	aks, err := store.ListAKs()
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Empty(t, aks)

	err = store.DeleteAK("3rd-ak")
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	err = store.DeleteAK("1st-ak")
	require.ErrorIs(t, err, ErrNoStorageConfigured)

	aks, err = store.ListAKs()
	require.ErrorIs(t, err, ErrNoStorageConfigured)
	require.Empty(t, aks)

	err = store.Persist()
	require.NoError(t, err)

	err = store.Load()
	require.NoError(t, err)
}

func TestFeedthroughStore_AKOperations(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := NewFeedthroughStore(NewDirstore(tempDir))

	ak1 := &AK{Name: "1st-ak"}
	ak2 := &AK{Name: "2nd-ak"}

	err := store.AddAK(ak1)
	require.NoError(t, err)

	err = store.AddAK(ak2)
	require.NoError(t, err)

	err = store.AddAK(ak1)
	require.EqualError(t, err, "already exists")

	k, err := store.GetAK("1st-ak")
	require.NoError(t, err)
	require.Equal(t, ak1, k)

	k.Data = []byte{1, 2, 3, 4}
	err = store.UpdateAK(k)
	require.NoError(t, err)

	k.Data = nil
	err = store.UpdateAK(k)
	require.NoError(t, err)

	k, err = store.GetAK("3rd-ak")
	require.EqualError(t, err, "not found")
	require.Nil(t, k)

	names := store.ListAKNames()
	require.Equal(t, []string{"1st-ak", "2nd-ak"}, names)

	aks, err := store.ListAKs()
	require.NoError(t, err)
	require.ElementsMatch(t, []*AK{ak1, ak2}, aks)

	err = store.DeleteAK("3rd-ak")
	require.EqualError(t, err, "not found")

	err = store.DeleteAK("1st-ak")
	require.NoError(t, err)

	aks, err = store.ListAKs()
	require.NoError(t, err)
	require.ElementsMatch(t, []*AK{ak2}, aks)

	err = store.Persist()
	require.NoError(t, err)

	err = store.Load()
	require.NoError(t, err)
}
