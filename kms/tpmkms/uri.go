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
	attestBy       string
	qualifyingData []byte
}

func parseNameURI(nameURI string) (o objectProperties, err error) {
	if nameURI == "" {
		return o, errors.New("empty URI not supported")
	}
	var u *uri.URI
	var parseErr error
	if u, parseErr = uri.ParseWithScheme(Scheme, nameURI); parseErr == nil {
		if name := u.Get("name"); name == "" {
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
		o.attestBy = u.Get("attest-by")
		if qualifyingData := u.GetEncoded("qualifying-data"); qualifyingData != nil {
			o.qualifyingData = qualifyingData
		}

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
