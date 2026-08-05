//go:build go1.27

package mldsa

import (
	"crypto/mldsa"
)

type PublicKey = mldsa.PublicKey

type PrivateKey = mldsa.PrivateKey

var (
	GenerateKey = mldsa.GenerateKey
	MLDSA44     = mldsa.MLDSA44
	MLDSA65     = mldsa.MLDSA65
	MLDSA87     = mldsa.MLDSA87
)
