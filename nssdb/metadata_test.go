package nssdb

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMetadata(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			got, err := db.GetMetadata(ctx, "password")
			require.NoError(t, err)

			assert.Equal(t, "password", got.ID)
			assert.NotEmpty(t, got.Item1)
			assert.NotEmpty(t, got.Item2)
		})

		t.Run(v.name("not found"), func(t *testing.T) {
			_, err := db.GetMetadata(ctx, "notfound")
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})
	}
}

func TestGetPassword(t *testing.T) {
	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			_, err := db.GetPassword(context.Background())
			require.NoError(t, err)
		})
	}
}
