//go:build !go1.27

package mldsa

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnsupported(t *testing.T) {
	assert.False(t, Supported)

	_, err := GenerateSigner(MLDSA65Name)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUnsupported))

	_, err = GenerateKey(MLDSA65())
	assert.True(t, errors.Is(err, ErrUnsupported))

	_, err = NewPrivateKey(MLDSA65(), nil)
	assert.True(t, errors.Is(err, ErrUnsupported))

	_, err = NewPublicKey(MLDSA65(), nil)
	assert.True(t, errors.Is(err, ErrUnsupported))

	err = Verify(&PublicKey{}, nil, nil, &Options{})
	assert.True(t, errors.Is(err, ErrUnsupported))
}
