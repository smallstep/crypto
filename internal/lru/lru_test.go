package lru

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	c := New[string, int](3)
	assert.Equal(t, 3, c.Capacity())
	assert.Equal(t, 0, c.Len())
	assert.Empty(t, c.Keys())

	assert.Panics(t, func() { New[string, int](0) })
	assert.Panics(t, func() { New[string, int](-1) })
}

func TestCache_GetPut(t *testing.T) {
	c := New[string, string](2)

	v, ok := c.Get("a")
	assert.False(t, ok)
	assert.Empty(t, v)

	c.Put("a", "1")
	c.Put("b", "2")
	assert.Equal(t, 2, c.Len())
	assert.Equal(t, []string{"a", "b"}, c.Keys())

	v, ok = c.Get("a")
	assert.True(t, ok)
	assert.Equal(t, "1", v)

	// Overwriting a key keeps the length and makes it the newest.
	c.Put("b", "22")
	v, ok = c.Get("b")
	assert.True(t, ok)
	assert.Equal(t, "22", v)
	assert.Equal(t, 2, c.Len())
	assert.Equal(t, []string{"a", "b"}, c.Keys())
}

func TestCache_Put_evicts(t *testing.T) {
	c := New[string, int](2)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	assert.Equal(t, 2, c.Len())
	assert.Equal(t, []string{"b", "c"}, c.Keys())

	_, ok := c.Get("a")
	assert.False(t, ok)

	// A hit on "b" makes "c" the eviction candidate.
	_, ok = c.Get("b")
	assert.True(t, ok)
	c.Put("d", 4)
	assert.Equal(t, []string{"b", "d"}, c.Keys())

	_, ok = c.Get("c")
	assert.False(t, ok)
}

func TestCache_Put_capacityOne(t *testing.T) {
	c := New[string, int](1)
	c.Put("a", 1)
	c.Put("b", 2)

	assert.Equal(t, 1, c.Len())
	assert.Equal(t, []string{"b"}, c.Keys())

	v, ok := c.Get("b")
	assert.True(t, ok)
	assert.Equal(t, 2, v)
}

func TestCache_structKey(t *testing.T) {
	type key struct {
		name string
		kind int
	}
	c := New[key, []byte](2)
	c.Put(key{"a", 1}, []byte("one"))
	c.Put(key{"a", 2}, []byte("two"))

	v, ok := c.Get(key{"a", 1})
	assert.True(t, ok)
	assert.Equal(t, []byte("one"), v)

	_, ok = c.Get(key{"a", 3})
	assert.False(t, ok)

	// {"a", 2} is now the least recently used entry.
	c.Put(key{"b", 1}, []byte("three"))
	assert.Equal(t, []key{{"a", 1}, {"b", 1}}, c.Keys())
}

func TestCache_Remove(t *testing.T) {
	c := New[string, int](3)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Put("c", 3)

	assert.False(t, c.Remove("z"))
	assert.True(t, c.Remove("b"))
	assert.False(t, c.Remove("b"))
	assert.Equal(t, 2, c.Len())
	assert.Equal(t, []string{"a", "c"}, c.Keys())

	// The freed slot is reusable, and the list is still intact after removing
	// from the middle.
	c.Put("d", 4)
	assert.Equal(t, []string{"a", "c", "d"}, c.Keys())

	assert.True(t, c.Remove("a"))
	assert.True(t, c.Remove("d"))
	assert.Equal(t, []string{"c"}, c.Keys())
}

func TestCache_Clear(t *testing.T) {
	c := New[string, int](2)
	c.Put("a", 1)
	c.Put("b", 2)

	c.Clear()
	assert.Equal(t, 0, c.Len())
	assert.Equal(t, 2, c.Capacity())
	assert.Empty(t, c.Keys())

	_, ok := c.Get("a")
	assert.False(t, ok)

	// The cache is still usable after clearing.
	c.Put("c", 3)
	assert.Equal(t, []string{"c"}, c.Keys())
	v, ok := c.Get("c")
	assert.True(t, ok)
	assert.Equal(t, 3, v)
}

func TestCache_concurrent(t *testing.T) {
	const capacity = 16
	c := New[int, int](capacity)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 200 {
				key := (i*200 + j) % 64
				c.Put(key, j)
				if v, ok := c.Get(key); ok {
					require.GreaterOrEqual(t, v, 0)
				}
				c.Remove(j % 64)
				c.Keys()
				c.Len()
			}
		})
	}
	wg.Wait()

	assert.LessOrEqual(t, c.Len(), capacity)
	assert.Len(t, c.Keys(), c.Len())
}

func ExampleNew() {
	c := New[string, int](2)
	c.Put("a", 1)
	c.Put("b", 2)
	c.Get("a")
	c.Put("c", 3)

	fmt.Println(c.Keys())
	// Output: [a c]
}
