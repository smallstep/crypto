package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromContext(t *testing.T) {
	t.Parallel()

	exp := new(Dirstore)
	got := FromContext(NewContext(context.Background(), exp))
	assert.Same(t, exp, got)
}

func TestFromContextPanics(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() { FromContext(context.Background()) })
}
