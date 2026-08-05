//go:build go1.27

package keyutil

import (
	"crypto/mldsa"

	"github.com/pkg/errors"
)

func extractKey(in any) (any, error) {
	switch in.(type) {
	case *mldsa.PublicKey, *mldsa.PrivateKey:
		return in, nil
	default:
		return nil, errors.Errorf("cannot extract the key from type '%T'", in)
	}
}
