package randutil

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSalt(t *testing.T) {
	sizes := []int{4, 8, 16, 32}
	for _, size := range sizes {
		a := Salt(size)
		b := Salt(size)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestBytes(t *testing.T) {
	sizes := []int{4, 8, 16, 32, 64, 128}
	for _, size := range sizes {
		a := Bytes(size)
		b := Bytes(size)
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestString(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9世界ñçàèìòù]+$`)
	chars := "0123456789世界ñçàèìòù"
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a := String(l, chars)
		assert.True(t, re.MatchString(a))
		b := String(l, chars)
		assert.True(t, re.MatchString(b))
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestHex(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9a-f]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a := Hex(l)
		assert.True(t, re.MatchString(a))
		b := Hex(l)
		assert.True(t, re.MatchString(b))
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestAlphanumeric(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9a-zA-Z]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a := Alphanumeric(l)
		assert.True(t, re.MatchString(a))
		b := Alphanumeric(l)
		assert.True(t, re.MatchString(b))
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestASCII(t *testing.T) {
	re := regexp.MustCompilePOSIX("^[\x21-\x7E]+$")
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a := ASCII(l)
		assert.True(t, re.MatchString(a))
		b := ASCII(l)
		assert.True(t, re.MatchString(b))
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestAlphabet(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[a-zA-Z]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a := Alphabet(l)
		assert.True(t, re.MatchString(a))
		b := Alphabet(l)
		assert.True(t, re.MatchString(b))
		// Most of the time
		assert.NotEqual(t, a, b)
	}
}

func TestUUIDv4(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuid := UUIDv4()
	assert.Len(t, uuid, 36)
	assert.True(t, re.MatchString(uuid))
}
