package nssdb

import (
	"bufio"
	"context"
	"database/sql"
	"embed"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata
var testdata embed.FS

var nssVersions []nssVersion

type nssVersion struct {
	version      string
	cert9        []byte
	key4         []byte
	certID       uint32
	pubKeyID     uint32
	privateKeyID uint32
}

func init() {
	entries, err := testdata.ReadDir("testdata")
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "v3.") {
			continue
		}

		cert9, err := testdata.ReadFile(filepath.Join("testdata", entry.Name(), "cert9.db"))
		if err != nil {
			panic(err)
		}

		key4, err := testdata.ReadFile(filepath.Join("testdata", entry.Name(), "key4.db"))
		if err != nil {
			panic(err)
		}

		v := nssVersion{
			version: entry.Name(),
			cert9:   cert9,
			key4:    key4,
		}

		ids, err := testdata.Open(filepath.Join("testdata", entry.Name(), "ids.txt"))
		if err != nil {
			panic(err)
		}
		defer ids.Close() //nolint:gocritic // defer in loop
		s := bufio.NewScanner(ids)
		for s.Scan() {
			words := strings.Fields(s.Text())
			if len(words) < 2 {
				continue
			}
			id, err := strconv.Atoi(words[1])
			if err != nil {
				panic(s.Text())
			}
			switch words[0] {
			case "certificate":
				v.certID = uint32(id)
			case "public-key":
				v.pubKeyID = uint32(id)
			case "private-key":
				v.privateKeyID = uint32(id)
			}
		}
		if err := s.Err(); err != nil {
			panic(err)
		}

		nssVersions = append(nssVersions, v)
	}
}

// connect creates a clean copy of the nss version's database in a temp dir
func (nss nssVersion) connect(t *testing.T) *NSSDB {
	t.Helper()
	db, _ := nss.connectDir(t)
	return db
}

func (nss nssVersion) connectDir(t *testing.T) (*NSSDB, string) {
	t.Helper()
	d := t.TempDir()

	cert9, err := os.Create(filepath.Join(d, "cert9.db"))
	require.NoError(t, err)
	_, err = cert9.Write(nss.cert9)
	require.NoError(t, err)

	key4, err := os.Create(filepath.Join(d, "key4.db"))
	require.NoError(t, err)
	_, err = key4.Write(nss.key4)
	require.NoError(t, err)

	db, err := New(d, nil)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	return db, d
}

func (nss nssVersion) name(s ...string) string {
	return strings.Join(append([]string{nss.version}, s...), " ")
}

func TestNSSDB_ListObjects(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		t.Run(v.name(), func(t *testing.T) {
			db := v.connect(t)

			objs, err := db.ListObjects(ctx)
			require.NoError(t, err)
			assert.Len(t, objs, 3)
		})
	}
}

func TestNSSDB_ListObjectsPublic(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		t.Run(v.name(), func(t *testing.T) {
			db := v.connect(t)

			objs, err := db.ListObjectsPublic(ctx)
			require.NoError(t, err)
			assert.Len(t, objs, 2)
		})
	}
}

func TestNSSDB_ListObjectsPrivate(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		t.Run(v.name(), func(t *testing.T) {
			db := v.connect(t)

			objs, err := db.ListObjectsPrivate(ctx)
			require.NoError(t, err)
			assert.Len(t, objs, 1)
		})
	}
}

func TestNSSDB_GetObjectPublic(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			obj, err := db.GetObjectPublic(ctx, v.certID)
			require.NoError(t, err)

			assert.Equal(t, v.certID, obj.ID)
			assert.NoError(t, obj.ValidateULong("CKA_CLASS", CKO_CERTIFICATE))
		})

		t.Run(v.name("not found"), func(t *testing.T) {
			_, err := db.GetObjectPublic(ctx, 7777)
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})
	}
}

func TestNSSDB_GetObjectPrivate(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			obj, err := db.GetObjectPrivate(ctx, v.privateKeyID)
			require.NoError(t, err)

			assert.Equal(t, v.privateKeyID, obj.ID)
			assert.NoError(t, obj.ValidateULong("CKA_CLASS", CKO_PRIVATE_KEY))
			assert.Len(t, obj.Metadata, 1)
		})

		t.Run(v.name("not found"), func(t *testing.T) {
			_, err := db.GetObjectPrivate(ctx, 7777)
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})
	}
}

func TestNSSDB_GetObject(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok public"), func(t *testing.T) {
			obj, err := db.GetObject(ctx, v.pubKeyID)
			require.NoError(t, err)
			assert.Equal(t, v.pubKeyID, obj.ID)
		})

		t.Run(v.name("ok private"), func(t *testing.T) {
			obj, err := db.GetObject(ctx, v.privateKeyID)
			require.NoError(t, err)
			assert.Equal(t, v.privateKeyID, obj.ID)
		})
	}
}

func TestNSSDB_InsertPublic(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			obj := &Object{
				ULongAttributes: map[string]uint32{
					"CKA_CLASS": CKO_CERTIFICATE,
				},
				Attributes: map[string][]byte{
					"CKA_VALUE": []byte("foo"),
				},
				EncryptedAttributes: map[string][]byte{},
			}

			id, err := db.InsertPublic(ctx, obj)
			require.NoError(t, err)
			assert.NotEmpty(t, id)
			obj.ID = id

			got, err := db.GetObjectPublic(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, obj, got)
		})

		t.Run(v.name("bad attribute"), func(t *testing.T) {
			obj := &Object{
				Attributes: map[string][]byte{
					"CKA_NOPE": {1},
				},
			}

			_, err := db.InsertPublic(ctx, obj)
			assert.ErrorContains(t, err, `db does not have a column for "CKA_NOPE"`)
		})
	}
}

func TestNSSDB_InsertPrivate(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			obj := &Object{
				ULongAttributes: map[string]uint32{
					"CKA_CLASS": CKO_CERTIFICATE,
				},
				Attributes: map[string][]byte{
					"CKA_VALUE": []byte("foo"),
				},
			}

			id, err := db.InsertPrivate(ctx, obj)
			require.NoError(t, err)
			assert.NotEmpty(t, id)
			obj.ID = id

			got, err := db.GetObjectPrivate(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, obj, got)
		})

		t.Run(v.name("bad attribute"), func(t *testing.T) {
			obj := &Object{
				Attributes: map[string][]byte{
					"CKA_NOPE": {1},
				},
			}

			_, err := db.InsertPrivate(ctx, obj)
			assert.ErrorContains(t, err, `db does not have a column for "CKA_NOPE"`)
		})
	}
}

func TestNSSDB_DeleteObjectPublic(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			err := db.DeleteObjectPublic(ctx, v.certID)
			require.NoError(t, err)

			_, err = db.GetObjectPublic(ctx, v.certID)
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})

		t.Run(v.name("ok not found"), func(t *testing.T) {
			err := db.DeleteObjectPublic(ctx, 7777)
			assert.NoError(t, err)
		})
	}
}

func TestNSSDB_DeleteObjectPrivate(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			err := db.DeleteObjectPrivate(ctx, v.privateKeyID)
			require.NoError(t, err)

			_, err = db.GetObjectPrivate(ctx, v.privateKeyID)
			assert.Error(t, err, sql.ErrNoRows)
			// verify metadata is deleted too
			sigKeyID := keySignatureID(v.privateKeyID)
			_, err = db.GetMetadata(ctx, sigKeyID)
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})

		t.Run(v.name("ok not found"), func(t *testing.T) {
			err := db.DeleteObjectPrivate(ctx, 7777)
			assert.NoError(t, err)
		})
	}
}

func TestNSSDB_DeleteObject(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok public"), func(t *testing.T) {
			err := db.DeleteObject(ctx, v.pubKeyID)
			assert.NoError(t, err)

			_, err = db.GetObject(ctx, v.pubKeyID)
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})

		t.Run(v.name("ok private"), func(t *testing.T) {
			err := db.DeleteObject(ctx, v.privateKeyID)
			require.NoError(t, err)

			_, err = db.GetObject(ctx, v.privateKeyID)
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})

		t.Run(v.name("ok not found"), func(t *testing.T) {
			err := db.DeleteObject(ctx, 7777)
			assert.NoError(t, err)
		})
	}
}

func TestNSSDB_Reset(t *testing.T) {
	ctx := context.Background()

	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.version, func(t *testing.T) {
			err := db.Reset(ctx)
			require.NoError(t, err)

			pubObjs, err := db.ListObjectsPublic(ctx)
			require.NoError(t, err)
			assert.Len(t, pubObjs, 0)

			privObjs, err := db.ListObjectsPublic(ctx)
			require.NoError(t, err)
			assert.Len(t, privObjs, 0)

			var metaID string
			err = db.Key.QueryRowContext(ctx, "SELECT id FROM metaData").Scan(&metaID)
			require.NoError(t, err)
			assert.Equal(t, "password", metaID)
		})
	}
}
