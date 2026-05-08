//go:build !notpmkms

package tpmkms

import (
	"errors"
	"fmt"

	"go.step.sm/crypto/kms/uri"
)

type objectProperties struct {
	name                      string
	ak                        bool
	tss2                      bool
	attestBy                  string
	qualifyingData            []byte
	path                      string
	storeLocation             string
	store                     string
	friendlyName              string
	description               string
	intermediateStoreLocation string
	intermediateStore         string
	skipFindCertificateKey    bool
	keyID                     string
	sha1                      string
	serial                    string
	issuer                    string
	// keyScope, if set, is one of "machine" or "user". It controls
	// whether the underlying private key lives in the local machine key
	// store or in the current user's key store, and is independent of
	// where the certificate is stored. When unset, [parseNameURI] derives
	// it from storeLocation for backwards compatibility (machine cert
	// store implies machine key scope).
	keyScope string
}

// machineKey returns true if the resolved key scope is "machine".
// When keyScope is unset on the object, the value is derived from
// storeLocation: "machine" → true, anything else → false.
func (o objectProperties) machineKey() bool {
	scope := o.keyScope
	if scope == "" {
		if o.storeLocation == "machine" {
			scope = "machine"
		} else {
			scope = "user"
		}
	}
	return scope == "machine"
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

		// store location and store options are used on Windows to override
		// which store(s) are used for storing and loading (intermediate) certificates
		// friendly-name and description are used on Windows to populate additional certificate
		// context properties to aid in retrieval
		o.storeLocation = u.Get("store-location")
		o.store = u.Get("store")
		o.friendlyName = u.Get("friendly-name")
		o.description = u.Get("description")
		o.intermediateStoreLocation = u.Get("intermediate-store-location")
		o.intermediateStore = u.Get("intermediate-store")
		o.skipFindCertificateKey = u.GetBool("skip-find-certificate-key")
		o.keyID = u.Get("key-id")
		o.sha1 = u.Get("sha1")
		o.serial = u.Get("serial")
		o.issuer = u.Get("issuer")

		// key-scope is independent of store-location: cert location and
		// key ownership are orthogonal Windows concepts. See [machineKey]
		// for the back-compat default when this is unset.
		o.keyScope = u.Get("key-scope")

		// validation
		if o.ak && o.attestBy != "" {
			return o, errors.New(`"ak" and "attest-by" are mutually exclusive`)
		}
		switch o.keyScope {
		case "", "machine", "user":
		default:
			return o, fmt.Errorf(`"key-scope" must be "machine" or "user", got %q`, o.keyScope)
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
