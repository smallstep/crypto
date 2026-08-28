// Package lru implements a fixed-capacity cache that evicts the least recently
// used entry when it is full.
package lru

import "sync"

// Cache is a cache of values of type T, keyed by K, holding a bounded number of
// entries. Once the cache is full, adding a new key evicts the one that was
// used least recently.
//
// A Cache returned by [New] is safe for concurrent use.
type Cache[K comparable, T any] interface {
	Get(key K) (value T, found bool)
	Put(key K, value T)
	Keys() []K
	Remove(key K) bool
	Clear()
	Capacity() int
	Len() int
}

var _ Cache[string, any] = (*cache[string, any])(nil)

// entry is a node in the cache's usage list. The list is circular and threaded
// through a sentinel, so the ends need no special casing: root.next is the most
// recently used entry and root.prev the least recently used one.
type entry[K comparable, T any] struct {
	prev, next *entry[K, T]
	key        K
	value      T
}

type cache[K comparable, T any] struct {
	mu       sync.Mutex
	capacity int
	entries  map[K]*entry[K, T]
	root     entry[K, T]
}

// New returns a cache holding at most capacity entries. It panics if capacity
// is not greater than zero.
func New[K comparable, T any](capacity int) Cache[K, T] {
	if capacity < 1 {
		panic("lru: capacity must be greater than zero")
	}
	c := &cache[K, T]{
		capacity: capacity,
		entries:  make(map[K]*entry[K, T], capacity),
	}
	c.root.prev, c.root.next = &c.root, &c.root
	return c
}

// Get returns the value stored under key, and reports whether it was found. A
// hit marks the entry as the most recently used one.
func (c *cache[K, T]) Get(key K) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		var zero T
		return zero, false
	}
	c.moveToFront(e)
	return e.value, true
}

// Put stores value under key, replacing any value already there, and marks it
// as the most recently used entry. If the cache is full, the least recently
// used entry is evicted to make room.
func (c *cache[K, T]) Put(key K, value T) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[key]; ok {
		e.value = value
		c.moveToFront(e)
		return
	}
	if len(c.entries) >= c.capacity {
		c.remove(c.root.prev)
	}
	e := &entry[K, T]{key: key, value: value}
	c.entries[key] = e
	c.pushFront(e)
}

// Keys returns the keys in the cache, from the least to the most recently used.
func (c *cache[K, T]) Keys() []K {
	c.mu.Lock()
	defer c.mu.Unlock()

	keys := make([]K, 0, len(c.entries))
	for e := c.root.prev; e != &c.root; e = e.prev {
		keys = append(keys, e.key)
	}
	return keys
}

// Remove deletes the entry stored under key and reports whether it was there.
func (c *cache[K, T]) Remove(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[key]
	if !ok {
		return false
	}
	c.remove(e)
	return true
}

// Clear removes every entry from the cache, leaving its capacity unchanged.
func (c *cache[K, T]) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	clear(c.entries)
	c.root.prev, c.root.next = &c.root, &c.root
}

// Capacity returns the maximum number of entries the cache holds.
func (c *cache[K, T]) Capacity() int {
	return c.capacity
}

// Len returns the number of entries currently in the cache.
func (c *cache[K, T]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.entries)
}

// pushFront links e in as the most recently used entry. The caller holds c.mu
// and e must not be linked in already.
func (c *cache[K, T]) pushFront(e *entry[K, T]) {
	e.prev, e.next = &c.root, c.root.next
	e.prev.next, e.next.prev = e, e
}

// moveToFront marks an entry already in the cache as the most recently used
// one. The caller holds c.mu.
func (c *cache[K, T]) moveToFront(e *entry[K, T]) {
	if c.root.next == e {
		return
	}
	e.prev.next, e.next.prev = e.next, e.prev
	c.pushFront(e)
}

// remove unlinks e and drops it from the key index. The caller holds c.mu.
func (c *cache[K, T]) remove(e *entry[K, T]) {
	e.prev.next, e.next.prev = e.next, e.prev
	e.prev, e.next = nil, nil
	delete(c.entries, e.key)
}
