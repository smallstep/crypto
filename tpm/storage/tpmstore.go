package storage

import "context"

type contextKey struct{}

// NewContext adds TPMStore `t` to the context.
func NewContext(ctx context.Context, t TPMStore) context.Context {
	return context.WithValue(ctx, contextKey{}, t)
}

// FromContext retrieves a TPMStore from the context.
//
// It panics when there's no TPMStore present.
func FromContext(ctx context.Context) TPMStore {
	return ctx.Value(contextKey{}).(TPMStore)
}

// TPMStore is the interface that TPM storage implementations
// need to implement.
type TPMStore interface {
	ListKeys() ([]*Key, error)
	ListKeyNames() []string
	GetKey(name string) (*Key, error)
	AddKey(key *Key) error
	UpdateKey(key *Key) error
	DeleteKey(name string) error

	ListAKs() ([]*AK, error)
	ListAKNames() []string
	GetAK(name string) (*AK, error)
	AddAK(ak *AK) error
	UpdateAK(ak *AK) error
	DeleteAK(name string) error

	Persist() error
	Load() error
}
