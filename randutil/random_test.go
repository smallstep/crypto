package randutil

import (
	"bytes"
	"crypto/rand"
	"errors"
	"regexp"
	"testing"

	"github.com/smallstep/assert"
)

func TestErrors(t *testing.T) {
	// with errors
	df := forceErrorRandReader()
	defer df()

	str, err := UUIDv4()
	assert.Error(t, err)
	assert.Len(t, 0, str)

	sizes := []int{4, 8, 16, 32}
	for _, size := range sizes {
		b, err := Salt(size)
		assert.Error(t, err)
		assert.Len(t, 0, b)

		str, err = String(size, "0123456789")
		assert.Error(t, err)
		assert.Len(t, 0, str)

		str, err = Hex(size)
		assert.Error(t, err)
		assert.Len(t, 0, str)

		str, err = Alphanumeric(size)
		assert.Error(t, err)
		assert.Len(t, 0, str)

		str, err = ASCII(size)
		assert.Error(t, err)
		assert.Len(t, 0, str)

		str, err = Alphabet(size)
		assert.Error(t, err)
		assert.Len(t, 0, str)
	}
}

func TestSalt(t *testing.T) {
	sizes := []int{4, 8, 16, 32}
	for _, size := range sizes {
		a, err := Salt(size)
		assert.NoError(t, err)
		b, err := Salt(size)
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestBytes(t *testing.T) {
	sizes := []int{4, 8, 16, 32, 64, 128}
	for _, size := range sizes {
		a, err := Bytes(size)
		assert.NoError(t, err)
		b, err := Bytes(size)
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestString(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9世界ñçàèìòù]+$`)
	chars := "0123456789世界ñçàèìòù"
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := String(l, chars)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := String(l, chars)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestHex(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9a-f]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := Hex(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := Hex(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestAlphanumeric(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9a-zA-Z]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := Alphanumeric(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := Alphanumeric(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestASCII(t *testing.T) {
	re := regexp.MustCompilePOSIX("^[\x21-\x7E]+$")
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := ASCII(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := ASCII(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestAlphabet(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[a-zA-Z]+$`)
	lengths := []int{4, 8, 16, 32}
	for _, l := range lengths {
		a, err := Alphabet(l)
		assert.True(t, re.MatchString(a))
		assert.NoError(t, err)
		b, err := Alphabet(l)
		assert.True(t, re.MatchString(b))
		assert.NoError(t, err)
		// Most of the time
		assert.NotEquals(t, a, b)
	}
}

func TestUUIDv4(t *testing.T) {
	re := regexp.MustCompilePOSIX(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuid, err := UUIDv4()
	assert.NoError(t, err)
	assert.Len(t, 36, uuid)
	assert.True(t, re.MatchString(uuid))

	b := make([]byte, 32)
	copy(b[16:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6})
	df := forceByteReader(b)
	defer df()

	tests := []struct {
		name    string
		want    string
		wantErr bool
	}{
		{"ok", "00000000-0000-4000-8000-000000000000", false},
		{"ok", "01020304-0506-4708-8900-010203040506", false},
		{"fail", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UUIDv4()
			if (err != nil) != tt.wantErr {
				t.Errorf("UUIDv4() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("UUIDv4() = %v, want %v", got, tt.want)
			}
		})
	}
}

type errorReader struct{}

func (r *errorReader) Read(p []byte) (int, error) {
	return 0, errors.New("an error")
}

func forceErrorRandReader() func() {
	old := rand.Reader
	rand.Reader = new(errorReader)
	return func() {
		rand.Reader = old
	}
}

func forceByteReader(b []byte) func() {
	old := rand.Reader
	rand.Reader = bytes.NewReader(b)
	return func() {
		rand.Reader = old
	}
}
