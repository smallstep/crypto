package utils

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMustUint64ConvertsValues(t *testing.T) {
	require.Equal(t, uint64(0), MustUint64(0))
	require.Equal(t, uint64(math.MaxInt64), MustUint64(int64(math.MaxInt64)))
	require.Equal(t, uint64(42), MustUint64(42))
}

func TestMustUint64PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { MustUint64(-1) })
}

func TestMustUint32ConvertsValues(t *testing.T) {
	require.Equal(t, uint32(0), MustUint32(0))
	require.Equal(t, uint32(math.MaxUint32), MustUint32(int64(math.MaxUint32)))
	require.Equal(t, uint32(42), MustUint32(42))
}

func TestMustUint32PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { MustUint32(-1) })
}

func TestMustUint32PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { MustUint32(int64(math.MaxUint32 + 1)) })
}

func TestMustUint16ConvertsValues(t *testing.T) {
	require.Equal(t, uint16(0), MustUint16(0))
	require.Equal(t, uint16(math.MaxUint16), MustUint16(math.MaxUint16))
	require.Equal(t, uint16(42), MustUint16(42))
}

func TestMustUint16PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { MustUint16(-1) })
}

func TestMustUint16PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { MustUint16(math.MaxUint16 + 1) })
}

func TestMustUint8ConvertsValues(t *testing.T) {
	require.Equal(t, uint8(0), MustUint8(0))
	require.Equal(t, uint8(math.MaxUint8), MustUint8(math.MaxUint8))
	require.Equal(t, uint8(42), MustUint8(42))
}

func TestMustUint8PanicsOnNegativeValue(t *testing.T) {
	require.Panics(t, func() { MustUint8(-1) })
}

func TestMustUint8PanicsOnLargeValue(t *testing.T) {
	require.Panics(t, func() { MustUint8(math.MaxUint8 + 1) })
}
