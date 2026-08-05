//go:build !go1.27

package keyutil

import "github.com/pkg/errors"

func extractKey(in any) (any, error) {
	return nil, errors.Errorf("cannot extract the key from type '%T'", in)
}
