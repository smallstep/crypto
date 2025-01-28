package nssdb

import (
	"context"
	"fmt"
)

type Metadata struct {
	ID    string
	Item1 []byte
	Item2 []byte
}

type Password struct {
	Salt              []byte
	EncryptedPassword []byte
}

// The schema of the metaData table is (id string, item1, item2)
func (db *NSSDB) GetMetadata(ctx context.Context, id string) (*Metadata, error) {
	entry := &Metadata{
		ID: id,
	}
	err := db.Key.QueryRowContext(ctx, "SELECT item1, item2 FROM metaData WHERE id = ?", id).Scan(&entry.Item1, &entry.Item2)
	if err != nil {
		return nil, fmt.Errorf("get metaData.%s: %w", id, err)
	}

	return entry, nil
}

func (db *NSSDB) GetPassword(ctx context.Context) (*Password, error) {
	meta, err := db.GetMetadata(ctx, "password")
	if err != nil {
		return nil, fmt.Errorf(`get "password" from metaData: %w`, err)
	}

	return &Password{
		Salt:              meta.Item1,
		EncryptedPassword: meta.Item2,
	}, nil
}

func (db *NSSDB) deleteSignatures(ctx context.Context, objectID uint32) error {
	id := keySignatureID(objectID)
	_, err := db.Key.ExecContext(ctx, "DELETE FROM metaData WHERE id = ?", id)
	return err
}
