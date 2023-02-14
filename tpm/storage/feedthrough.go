package storage

// FeedthroughStore is a TPMStore that feeds through storage operations
// to the underlying TPMStore. If no backing TPMStore is set, the operations
// effectively become NOOPs.
type FeedthroughStore struct {
	store TPMStore
}

func NewFeedthroughStore(store TPMStore) *FeedthroughStore {
	return &FeedthroughStore{
		store: store,
	}
}

func (f *FeedthroughStore) ListKeys() ([]*Key, error) {
	if f.store == nil {
		return nil, nil
	}
	return f.store.ListKeys()
}

func (f *FeedthroughStore) ListKeyNames() []string {
	if f.store == nil {
		return []string{}
	}
	return f.store.ListKeyNames()
}

func (f *FeedthroughStore) GetKey(name string) (*Key, error) {
	if f.store == nil {
		return nil, nil
	}
	return f.store.GetKey(name)
}

func (f *FeedthroughStore) AddKey(key *Key) error {
	if f.store == nil {
		return nil
	}
	return f.store.AddKey(key)
}

func (f *FeedthroughStore) DeleteKey(name string) error {
	if f.store == nil {
		return nil
	}
	return f.store.DeleteKey(name)
}

func (f *FeedthroughStore) ListAKs() ([]*AK, error) {
	if f.store == nil {
		return nil, nil
	}
	return f.store.ListAKs()
}

func (f *FeedthroughStore) ListAKNames() []string {
	if f.store == nil {
		return []string{}
	}
	return f.store.ListAKNames()
}

func (f *FeedthroughStore) GetAK(name string) (*AK, error) {
	if f.store == nil {
		return nil, nil
	}
	return f.store.GetAK(name)
}

func (f *FeedthroughStore) AddAK(ak *AK) error {
	if f.store == nil {
		return nil
	}
	return f.store.AddAK(ak)
}

func (f *FeedthroughStore) DeleteAK(name string) error {
	if f.store == nil {
		return nil
	}
	return f.store.DeleteAK(name)
}

func (f *FeedthroughStore) Persist() error {
	if f.store == nil {
		return nil
	}
	return f.store.Persist()
}

func (f *FeedthroughStore) Load() error {
	if f.store == nil {
		return nil
	}
	return f.store.Load()
}

var _ TPMStore = (*FeedthroughStore)(nil)
