//go:build !go1.24

package fipsutil

// Enabled reports whether the cryptography libraries are operating in FIPS
// 140-3 mode.
//
// On Go < 1.24 it will return always false.
func Enabled() bool {
	return false
}

// Only reports whether the cryptography libraries are operating in FIPS 140-3
// "only" mode, when non-approved cryptography functions will additionally
// return errors or panic.
//
// On Go < 1.24 it will return always false.
func Only() bool {
	return false
}
