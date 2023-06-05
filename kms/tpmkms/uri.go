//go:build !notpmkms
// +build !notpmkms

package tpmkms

import (
	"errors"
	"fmt"
	"strings"

	"go.step.sm/crypto/kms/uri"
)

type objectProperties struct {
	uri            string
	name           string
	ak             bool
	attestBy       string
	qualifyingData []byte
}

func parseNameURI(nameURI string) (o objectProperties, err error) {
	o.uri = nameURI

	if nameURI == "" {
		return
	}

	// TODO(hs): support case in which `name` key is not provided
	if strings.HasPrefix(nameURI, "tpmkms:") {
		u, err := uri.Parse(nameURI)
		if err != nil {
			return o, fmt.Errorf("failed parsing %q as URL: %w", nameURI, err)
		}
		o.name = u.Get("name")
		o.ak = u.GetBool("ak")
		o.attestBy = u.Get("attest-by")
		if qualifyingData := u.GetEncoded("qualifying-data"); qualifyingData != nil {
			o.qualifyingData = qualifyingData
		}
	}

	if o.ak && o.attestBy != "" {
		return o, errors.New(`"ak" and "attest-by" are mutually exclusive`)
	}

	return
}
