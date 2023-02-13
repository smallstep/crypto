package storage

import "context"

type contextKey struct{}

func NewContext(ctx context.Context, t TPMStore) context.Context {
	return context.WithValue(ctx, contextKey{}, t)
}

func FromContext(ctx context.Context) TPMStore {
	return ctx.Value(contextKey{}).(TPMStore)
}

type TPMStore interface {
	ListKeys() ([]*Key, error)
	ListKeyNames() []string
	GetKey(name string) (*Key, error)
	AddKey(key *Key) error
	DeleteKey(name string) error

	ListAKs() ([]*AK, error)
	ListAKNames() []string
	GetAK(name string) (*AK, error)
	AddAK(ak *AK) error
	DeleteAK(name string) error

	Persist() error
	Load() error
}
