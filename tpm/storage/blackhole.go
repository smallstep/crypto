package storage

import "context"

// BlackHole returns a [FeedthroughStore] without a backing
// storage, effectively resulting in no persistence. Note
// that some operations do require persistence, in which
// case [ErrNoStorageConfigured] will be returned by the
// [FeedthroughStore].
func BlackHole() TPMStore {
	return NewFeedthroughStore(nil)
}

// BlackholeContext adds a new BlackHole storage to the context.
func BlackHoleContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = NewContext(ctx, BlackHole())
	return ctx
}
