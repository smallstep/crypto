package key

import "io"

// Create creates a new TPM key without attesting it and returns a
// serialized representation of it. The serialized format is compatible
// with the `go-attestation` format. Most of the code in this package
// is in fact copied from `go-attestation`, as large parts of its code
// are not publicly available at the moment. The code is useful, as it
// allows keys to be created in exactly the same way `go-attestation`
// creates them, except without attesting them. Both types of keys can
// be used for similar purposes, but only keys attested by an AK can be
// proved to be actually only resident in a TPM.
//
// TODO: it might be an option to make some more things public in the
// `go-attestation` package, or to change some of the logic of the
// `NewKey` function that makes the AK optional.
func Create(rwc io.ReadWriteCloser, keyName string, config CreateConfig) ([]byte, error) {
	return create(rwc, keyName, config)
}
