//go:build go1.27

package mldsa

import (
	"crypto/mldsa"
)

// Enabled returns if mdlsa package is implemented. It will return true in Go
// 1.27+ and false on lower versions.
func Enabled() bool {
	return true
}

type Options = mldsa.Options

type Parameters = mldsa.Parameters

type PrivateKey = mldsa.PrivateKey

type PublicKey = mldsa.PublicKey

var (
	GenerateKey = mldsa.GenerateKey
	Verify      = mldsa.Verify
	MLDSA44     = mldsa.MLDSA44
	MLDSA65     = mldsa.MLDSA65
	MLDSA87     = mldsa.MLDSA87
)
