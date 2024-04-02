//go:build !notpmkms
// +build !notpmkms

package tpmkms

import (
	"errors"
	"fmt"

	"go.step.sm/crypto/kms/uri"
)

type objectProperties struct {
	name           string
	ak             bool
	tss2           bool
	attestBy       string
	qualifyingData []byte
	path           string
	storeLocation  string
	store          string
}

func parseNameURI(nameURI string) (o objectProperties, err error) {
	if nameURI == "" {
		return o, errors.New("empty URI not supported")
	}
	var u *uri.URI
	var parseErr error
	if u, parseErr = uri.ParseWithScheme(Scheme, nameURI); parseErr == nil {
		o.path = u.Get("path")
		if name := u.Get("name"); name == "" && o.path == "" {
			if len(u.Values) == 1 {
				o.name = u.Opaque
			} else {
				for k, v := range u.Values {
					if len(v) == 1 && v[0] == "" {
						o.name = k
						break
					}
				}
			}
		} else {
			o.name = name
		}

		o.ak = u.GetBool("ak")
		o.tss2 = u.GetBool("tss2")
		o.attestBy = u.Get("attest-by")
		if qualifyingData := u.GetEncoded("qualifying-data"); qualifyingData != nil {
			o.qualifyingData = qualifyingData
		}

		// store location and store are only used on Windows
		o.storeLocation = u.Get("store-location")
		o.store = u.Get("store")

		// validation
		if o.ak && o.attestBy != "" {
			return o, errors.New(`"ak" and "attest-by" are mutually exclusive`)
		}

		return
	}

	if u, parseErr := uri.Parse(nameURI); parseErr == nil {
		if u.Scheme != Scheme {
			return o, fmt.Errorf("URI scheme %q is not supported", u.Scheme)
		}
	}

	o.name = nameURI // assumes there's no other properties encoded; just a name
	return
}
