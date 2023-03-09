//go:build !noazurekms
// +build !noazurekms

package azurekms

import (
	"context"
	"crypto"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/pkg/errors"
	"go.step.sm/crypto/jose"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
)

// defaultContext returns the default context used in requests to azure.
func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// getKeyName returns the uri of the key vault key.
func getKeyName(vault, name string, bundle keyvault.KeyBundle) string {
	if bundle.Key != nil && bundle.Key.Kid != nil {
		if u, err := url.Parse(*bundle.Key.Kid); err == nil {
			host := strings.SplitN(u.Host, ".", 2)
			path := strings.Split(u.Path, "/")
			if len(host) == 2 && len(path) == 4 {
				uu := uri.New(Scheme, url.Values{
					"vault": []string{host[0]},
					"name":  []string{path[2]},
				})
				uu.RawQuery = url.Values{"version": []string{path[3]}}.Encode()
				return uu.String()
			}
		}
	}
	// Fallback to URI without id.
	return uri.New(Scheme, url.Values{
		"vault": []string{vault},
		"name":  []string{name},
	}).String()
}

// parseKeyName returns the key vault, name and version from URIs like:
//
//   - azurekms:vault=key-vault;name=key-name
//   - azurekms:vault=key-vault;name=key-name?version=key-id
//   - azurekms:vault=key-vault;name=key-name?version=key-id&hsm=true
//
// The key-id defines the version of the key, if it is not passed the latest
// version will be used.
//
// HSM can also be passed to define the protection level if this is not given in
// CreateQuery.
func parseKeyName(rawURI string, defaults DefaultOptions) (vault, name, version, dnsSuffix string, hsm bool, err error) {
	var u *uri.URI

	u, err = uri.ParseWithScheme(Scheme, rawURI)
	if err != nil {
		return
	}
	if name = u.Get("name"); name == "" {
		err = errors.Errorf("key uri %s is not valid: name is missing", rawURI)
		return
	}
	if vault = u.Get("vault"); vault == "" {
		if defaults.Vault == "" {
			name = ""
			err = errors.Errorf("key uri %s is not valid: vault is missing", rawURI)
			return
		}
		vault = defaults.Vault
	}
	if u.Get("hsm") == "" {
		hsm = (defaults.ProtectionLevel == apiv1.HSM)
	} else {
		hsm = u.GetBool("hsm")
	}

	version = u.Get("version")
	dnsSuffix = defaults.Environment.KeyVaultDNSSuffix

	return
}

func vaultBaseURL(vault, dnsSuffix string) string {
	if dnsSuffix == "" {
		return "https://" + vault + ".vault.azure.net/"
	}

	return "https://" + vault + "." + dnsSuffix + "/"
}

func convertKey(key *keyvault.JSONWebKey) (crypto.PublicKey, error) {
	b, err := json.Marshal(key)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling key")
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(b); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling key")
	}
	return jwk.Key, nil
}
