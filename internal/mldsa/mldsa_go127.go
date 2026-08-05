//go:build go1.27

package mldsa

import (
	"crypto/mldsa"
)

type PublicKey = mldsa.PublicKey

type PrivateKey = mldsa.PrivateKey
