package apiv1

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyError(t *testing.T) {
	sentinel := errors.New("boom")
	err := &KeyError{Name: "tpmkms:name=key1", Err: sentinel}

	assert.Equal(t, `key "tpmkms:name=key1": boom`, err.Error())
	assert.Equal(t, sentinel, err.Unwrap())
	assert.ErrorIs(t, err, sentinel)

	// wrapped through fmt.Errorf the underlying sentinel is still reachable.
	wrapped := fmt.Errorf("context: %w", err)
	assert.ErrorIs(t, wrapped, sentinel)

	var ke *KeyError
	require.True(t, errors.As(wrapped, &ke))
	assert.Equal(t, "tpmkms:name=key1", ke.Name)
}

func TestPartialError(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		err := &PartialError{}
		assert.Equal(t, "partial failure", err.Error())
		assert.Empty(t, err.Unwrap())
	})

	t.Run("single", func(t *testing.T) {
		err := &PartialError{Errors: []error{errors.New("only")}}
		assert.Equal(t, "1 item failed: only", err.Error())
		assert.Len(t, err.Unwrap(), 1)
	})

	t.Run("multiple", func(t *testing.T) {
		err := &PartialError{Errors: []error{errors.New("a"), errors.New("b")}}
		assert.Contains(t, err.Error(), "2 items failed")
	})

	t.Run("errors.As and Is via Unwrap", func(t *testing.T) {
		sentinel := errors.New("bad keyset")
		ke := &KeyError{Name: "tpmkms:name=key2", Err: sentinel}
		err := error(&PartialError{Errors: []error{ke}})

		// extractable as the partial error itself...
		var pe *PartialError
		require.True(t, errors.As(err, &pe))
		require.Len(t, pe.Errors, 1)

		// ...and the contained members are reachable through Unwrap() []error.
		var got *KeyError
		require.True(t, errors.As(err, &got))
		assert.Equal(t, "tpmkms:name=key2", got.Name)
		assert.ErrorIs(t, err, sentinel)

		// still works when wrapped.
		wrapped := fmt.Errorf("search failed: %w", err)
		var pe2 *PartialError
		assert.True(t, errors.As(wrapped, &pe2))
		assert.ErrorIs(t, wrapped, sentinel)
	})
}
