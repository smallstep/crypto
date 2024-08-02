package storage

import (
	"testing"

	"github.com/peterbourgon/diskv/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_transform(t *testing.T) {
	t.Parallel()

	got := advancedTransform("/path/to/file")
	assert.Equal(t, &diskv.PathKey{Path: []string{"", "path", "to"}, FileName: "file.tpmobj"}, got)

	got = advancedTransform("path/to/file")
	assert.Equal(t, &diskv.PathKey{Path: []string{"path", "to"}, FileName: "file.tpmobj"}, got)

	got = advancedTransform("file.txt")
	assert.Equal(t, &diskv.PathKey{Path: []string{}, FileName: "file.txt.tpmobj"}, got)
}

func Test_inverseTransform(t *testing.T) {
	t.Parallel()

	got := inverseTransform(&diskv.PathKey{FileName: "file.txt.notpmkey"})
	assert.Equal(t, "", got)

	got = inverseTransform(&diskv.PathKey{FileName: "file.txt.tpmobj"})
	assert.Equal(t, "file.txt", got)

	got = inverseTransform(&diskv.PathKey{Path: []string{"path", "to"}, FileName: "file.tpmobj"})
	assert.Equal(t, "path/to/file", got)

	got = inverseTransform(&diskv.PathKey{Path: []string{"", "path", "to"}, FileName: "file.tpmobj"})
	assert.Equal(t, "/path/to/file", got)
}

func TestDirstore_KeyOperations(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := NewDirstore(tempDir)
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
}

func TestDirstore_AKOperations(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	store := NewDirstore(tempDir)
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
}
