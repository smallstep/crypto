//go:build !windows

package key

import "crypto"

func adopt(string, AdoptConfig) ([]byte, crypto.PublicKey, error) {
	return nil, nil, ErrAdoptUnsupported
}
