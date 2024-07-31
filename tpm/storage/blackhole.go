package storage

import (
	"context"
	"errors"
)

var (
	errBlackHole = errors.New("blackhole: no tpm store configured")

	bh TPMStore = blackHole{}
)

// BlackHole returns a [TMPStorage] that reports an appropriate error for all calls it is not
// able to support.
func BlackHole() TPMStore { return bh }

// BlackholeContext adds a new BlackHole storage to the context.
func BlackHoleContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx = NewContext(ctx, BlackHole())
	return ctx
}

type blackHole struct{}

func (blackHole) ListKeys() ([]*Key, error) { return nil, nil }

func (blackHole) ListKeyNames() []string { return nil }

func (blackHole) GetKey(string) (*Key, error) { return nil, ErrNotFound }

func (blackHole) AddKey(*Key) error { return errBlackHole }

func (blackHole) UpdateKey(*Key) error { return errBlackHole }

func (blackHole) DeleteKey(string) error { return ErrNotFound }

func (blackHole) ListAKs() ([]*AK, error) { return nil, nil }

func (blackHole) ListAKNames() []string { return nil }

func (blackHole) GetAK(string) (*AK, error) { return nil, ErrNotFound }

func (blackHole) AddAK(*AK) error { return errBlackHole }

func (blackHole) UpdateAK(*AK) error { return errBlackHole }

func (blackHole) DeleteAK(string) error { return ErrNotFound }

func (blackHole) Persist() error { return errBlackHole }

func (blackHole) Load() error { return nil }
