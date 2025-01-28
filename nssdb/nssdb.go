package nssdb

import (
	"context"
	"crypto/sha1" //nolint:gosec // NSS uses sha1
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	// enable sql driver
	_ "modernc.org/sqlite"
)

var columnNames = make(map[string]string, len(columns))

func init() {
	for k, v := range columns {
		columnNames[v] = k
	}
}

type NSSDB struct {
	Key      *sql.DB
	Cert     *sql.DB
	columns  []string
	colTable map[string]bool
	// aka "intermediate key", this is derived from the user-provided password and
	// the "global salt" in the metaData. This is used as input to pbkdf2 for all
	// encryption and signing operations.
	passKey       []byte
	emptyPassword bool
}

func (db *NSSDB) Close() error {
	if err := db.Key.Close(); err != nil {
		return fmt.Errorf("close key db: %w", err)
	}
	if err := db.Cert.Close(); err != nil {
		return fmt.Errorf("close cert db: %w", err)
	}
	return nil
}

// New opens connections to the cert9 and key4 sqlite databases in the provided
// directory. It defaults to the current directory if not set. The password
// argument is not required if the NSS database was created with the
// --empty-password flag.
func New(dir string, pw []byte) (*NSSDB, error) {
	if dir == "" {
		dir = "."
	}
	keyfile := filepath.Join(dir, "key4.db")
	certfile := filepath.Join(dir, "cert9.db")

	if _, err := os.Stat(keyfile); err != nil {
		return nil, fmt.Errorf("no nss database found in %q", dir)
	}
	if _, err := os.Stat(certfile); err != nil {
		return nil, fmt.Errorf("no nss database found in %q", dir)
	}

	keydb, err := sql.Open("sqlite", "file:"+keyfile)
	if err != nil {
		return nil, fmt.Errorf("open keydb %q: %w", keyfile, err)
	}

	certdb, err := sql.Open("sqlite", "file:"+certfile)
	if err != nil {
		return nil, fmt.Errorf("open certdb %q: %w", certfile, err)
	}

	// For backward and forward compatibility we need to know what columns are in
	// the nssPrivate and nssPublic tables. They share the same schema.
	rows, err := certdb.Query("SELECT * FROM nssPublic LIMIT 0")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dbcolumns []string
	colTable := map[string]bool{}
	cols, err := rows.ColumnTypes()
	if err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, col := range cols {
		name := col.Name()
		if _, ok := columnNames[name]; !ok {
			// ignore any unknown columns
			continue
		}
		dbcolumns = append(dbcolumns, name)
		colTable[name] = true
	}

	var globalSalt []byte
	err = keydb.QueryRow(`SELECT item1 FROM metaData WHERE id = 'password'`).Scan(&globalSalt)
	if err != nil {
		return nil, fmt.Errorf("get salt from metaData table in key db: %w", err)
	}

	return &NSSDB{
		Key:      keydb,
		Cert:     certdb,
		columns:  dbcolumns,
		colTable: colTable,
		passKey:  intermediateKey(pw, globalSalt),
	}, nil
}

// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkpwd.c#L89
func intermediateKey(password, salt []byte) []byte {
	//nolint:gosec // NSS uses sha1
	h := sha1.New()
	h.Write(salt)
	h.Write(password)
	return h.Sum(nil)
}

// ListObjects fetches all objects in the nssPublic and nssPrivate tables.
func (db *NSSDB) ListObjects(ctx context.Context) ([]*Object, error) {
	pubObjs, err := db.ListObjectsPublic(ctx)
	if err != nil {
		return nil, err
	}
	privateObjs, err := db.ListObjectsPrivate(ctx)
	if err != nil {
		return nil, err
	}
	return append(privateObjs, pubObjs...), nil
}

// ListObjectsPublic fetches all objects in the nssPublic table in the cert db.
func (db *NSSDB) ListObjectsPublic(ctx context.Context) ([]*Object, error) {
	//nolint:gosec // trusted strings
	q := fmt.Sprintf("SELECT id, %s FROM nssPublic", strings.Join(db.columns, ", "))
	rows, err := db.Cert.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	return db.scanObjects(ctx, rows, false)
}

// ListObjectPrivate fetches all rows in the nssPrivate table in the key db.
func (db *NSSDB) ListObjectsPrivate(ctx context.Context) ([]*Object, error) {
	//nolint:gosec // trusted strings
	q := fmt.Sprintf("SELECT id, %s FROM nssPrivate", strings.Join(db.columns, ", "))
	rows, err := db.Key.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	return db.scanObjects(ctx, rows, false)
}

// GetObject fetches a single object by id from either the nssPublic table in the cert db
// or the nssPrivate table in the key db if not found in nssPublic.
func (db *NSSDB) GetObject(ctx context.Context, id uint32) (*Object, error) {
	obj, err := db.GetObjectPublic(ctx, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		return obj, nil
	}
	return db.GetObjectPrivate(ctx, id)
}

// GetObjectPublic fetches a single object by id from the nssPublic table in the cert db.
func (db *NSSDB) GetObjectPublic(ctx context.Context, id uint32) (*Object, error) {
	//nolint:gosec // trusted strings
	q := fmt.Sprintf("SELECT id, %s FROM nssPublic WHERE id = ?", strings.Join(db.columns, ", "))
	rows, err := db.Cert.QueryContext(ctx, q, id)
	if err != nil {
		return nil, err
	}
	return db.scanObject(ctx, rows, false)
}

// GetObjectPrivate fetches a single object by id from the nssPrivate table in
// the key db.
func (db *NSSDB) GetObjectPrivate(ctx context.Context, id uint32) (*Object, error) {
	//nolint:gosec // trusted strings
	q := fmt.Sprintf("SELECT id, %s FROM nssPrivate WHERE id = ?", strings.Join(db.columns, ", "))
	rows, err := db.Key.QueryContext(ctx, q, id)
	if err != nil {
		return nil, err
	}
	obj, err := db.scanObject(ctx, rows, true)
	if err != nil {
		return nil, err
	}
	for k, v := range obj.EncryptedAttributes {
		plaintext, err := db.decrypt(v)
		if err != nil {
			return nil, fmt.Errorf("decrypt %s: %w", k, err)
		}
		obj.Attributes[k] = plaintext
	}
	return obj, nil
}

// InsertPublic adds an object to the nssPublic table of the cert db.
func (db *NSSDB) InsertPublic(ctx context.Context, obj *Object) (uint32, error) {
	id, err := db.getObjectID(ctx)
	if err != nil {
		return 0, fmt.Errorf("get new object id: %w", err)
	}
	obj.ID = id

	if err := db.insert(ctx, obj, false); err != nil {
		return 0, err
	}
	return id, nil
}

// InsertPrivate adds an object to the nssPrivate table of the key db.
func (db *NSSDB) InsertPrivate(ctx context.Context, obj *Object) (uint32, error) {
	id, err := db.getObjectID(ctx)
	if err != nil {
		return 0, fmt.Errorf("get new object id: %w", err)
	}
	obj.ID = id
	obj.EncryptedAttributes = map[string][]byte{}
	for k, plaintext := range obj.Attributes {
		if !privateAttributes[k] {
			continue
		}
		encrypted, err := db.encrypt(plaintext)
		if err != nil {
			return 0, fmt.Errorf("encrypt %s: %w", k, err)
		}
		obj.EncryptedAttributes[k] = encrypted

		metadata, err := db.sign(id, plaintext)
		if err != nil {
			return 0, err
		}
		obj.Metadata = append(obj.Metadata, metadata)
	}
	if err := db.insert(ctx, obj, true); err != nil {
		return 0, err
	}
	return id, nil
}

func (db *NSSDB) insert(ctx context.Context, obj *Object, private bool) error {
	cols := []string{"id"}
	vals := []any{obj.ID}
	params := []string{"?"}

	for name, data := range obj.Attributes {
		if _, ok := obj.EncryptedAttributes[name]; ok {
			// insert the encrypted value, not the plaintext value
			continue
		}
		col := columns[name]
		if _, ok := db.colTable[col]; !ok {
			return fmt.Errorf("db does not have a column for %q", name)
		}
		cols = append(cols, col)
		vals = append(vals, data)
		params = append(params, "?")
	}
	for name, data := range obj.EncryptedAttributes {
		col := columns[name]
		if _, ok := db.colTable[col]; !ok {
			return fmt.Errorf("db does not have a column for %q", name)
		}
		cols = append(cols, col)
		vals = append(vals, data)
		params = append(params, "?")
	}
	for name, u := range obj.ULongAttributes {
		col := columns[name]
		if _, ok := db.colTable[col]; !ok {
			return fmt.Errorf("db does not have a column for %q", name)
		}
		cols = append(cols, col)
		vals = append(vals, encodeDBUlong(u))
		params = append(params, "?")
	}

	certTx, err := db.Cert.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer certTx.Rollback()
	keyTx, err := db.Key.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer keyTx.Rollback()
	if private {
		//nolint:gosec // trusted strings
		q := fmt.Sprintf("INSERT INTO nssPrivate (%s) VALUES (%s)", strings.Join(cols, ", "), strings.Join(params, ", "))
		if _, err := keyTx.ExecContext(ctx, q, vals...); err != nil {
			return err
		}
	} else {
		//nolint:gosec // trusted strings
		q := fmt.Sprintf("INSERT INTO nssPublic (%s) VALUES (%s)", strings.Join(cols, ", "), strings.Join(params, ", "))
		if _, err := certTx.ExecContext(ctx, q, vals...); err != nil {
			return err
		}
	}

	for _, metadata := range obj.Metadata {
		const q = "INSERT INTO metaData (id, item1, item2) VALUES (?, ?, ?)"
		if _, err := keyTx.ExecContext(ctx, q, metadata.ID, metadata.Item1, metadata.Item2); err != nil {
			return err
		}
	}
	if err := keyTx.Commit(); err != nil {
		return err
	}
	if err := certTx.Commit(); err != nil {
		return err
	}

	return nil
}

// Delete deletes an object.
func (db *NSSDB) DeleteObject(ctx context.Context, id uint32) error {
	if err := db.DeleteObjectPublic(ctx, id); err != nil {
		return err
	}
	if err := db.DeleteObjectPrivate(ctx, id); err != nil {
		return err
	}
	return nil
}

// DeletePublic deletes an object from the nssPublic database in the cert db.
func (db *NSSDB) DeleteObjectPublic(ctx context.Context, id uint32) error {
	_, err := db.Cert.ExecContext(ctx, "DELETE FROM nssPublic WHERE id = ?", id)
	return err
}

// DeletePrivate deletes an object from the nssPrivate database in the key db.
func (db *NSSDB) DeleteObjectPrivate(ctx context.Context, id uint32) error {
	_, err := db.Key.ExecContext(ctx, "DELETE FROM nssPrivate WHERE id = ?", id)
	if err != nil {
		return err
	}
	err = db.deleteSignatures(ctx, id)
	if err != nil {
		return fmt.Errorf("delete object metadata: %w", err)
	}
	return nil
}

// Reset deletes all objects and their metadata from the certificate and key
// databases. It does not delete the password from the metaData table.
func (db *NSSDB) Reset(ctx context.Context) error {
	certTx, err := db.Cert.BeginTx(ctx, nil)
	if err != nil {
		return nil
	}
	defer certTx.Rollback()
	keyTx, err := db.Key.BeginTx(ctx, nil)
	if err != nil {
		return nil
	}
	defer keyTx.Rollback()
	_, err = certTx.ExecContext(ctx, "DELETE FROM nssPublic")
	if err != nil {
		return err
	}
	_, err = keyTx.ExecContext(ctx, "DELETE FROM nssPrivate")
	if err != nil {
		return err
	}
	_, err = keyTx.ExecContext(ctx, `DELETE FROM metaData WHERE id <> "password"`)
	if err != nil {
		return err
	}

	if err := certTx.Commit(); err != nil {
		return err
	}
	if err := keyTx.Commit(); err != nil {
		return err
	}

	return nil
}

func (db *NSSDB) scanObject(ctx context.Context, rows *sql.Rows, private bool) (*Object, error) {
	objects, err := db.scanObjects(ctx, rows, private)
	if err != nil {
		return nil, err
	}

	if len(objects) == 0 {
		return nil, sql.ErrNoRows
	}

	return objects[0], nil
}

func (db *NSSDB) scanObjects(ctx context.Context, rows *sql.Rows, private bool) ([]*Object, error) {
	objects := []*Object{}

	for rows.Next() {
		object, err := db.scan(ctx, rows, private)
		if err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return objects, nil
}

func (db *NSSDB) scan(ctx context.Context, rows *sql.Rows, private bool) (*Object, error) {
	row := &Object{
		Attributes:          map[string][]byte{},
		ULongAttributes:     map[string]uint32{},
		EncryptedAttributes: map[string][]byte{},
	}
	dest := make([]any, len(db.columns)+1)
	id := sql.NullInt64{}
	dest[0] = &id
	for i := range db.columns {
		dest[i+1] = &sql.Null[[]byte]{}
	}
	err := rows.Scan(dest...)
	if err != nil {
		return nil, err
	}
	for i, dst := range dest[1:] {
		col := db.columns[i]
		name := columnNames[col]

		b := dst.(*sql.Null[[]byte])
		if b.Valid {
			data := b.V
			if _, ok := ulongAttributes[name]; ok {
				row.ULongAttributes[name] = decodeDBUlong(data)
			} else if _, ok := privateAttributes[name]; ok && private {
				// private attributes are only encrypted in nssPrivate in the key db
				row.EncryptedAttributes[name] = data
			} else {
				row.Attributes[name] = data
			}
		}
	}
	row.ID = uint32(id.Int64)
	if _, ok := row.EncryptedAttributes["CKA_VALUE"]; ok {
		ckaValSignatureID := keySignatureID(row.ID)
		md, err := db.GetMetadata(ctx, ckaValSignatureID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return nil, err
		default:
			row.Metadata = append(row.Metadata, md)
		}
	}
	return row, nil
}

// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sdb.c#L1260
func (db *NSSDB) getObjectID(ctx context.Context) (uint32, error) {
	id := uint32(time.Now().Unix() & 0x3fffffff)

	for i := 0; i < 0x40000000; i++ {
		id &= 0x3fffffff
		if id == 0 {
			continue
		}
		_, err := db.GetObject(ctx, id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return id, nil
		case err != nil:
			return 0, err
		}
		id++
	}

	return 0, errors.New("no id available")
}
