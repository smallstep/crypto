//go:build !noazurekms
// +build !noazurekms

package azurekms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
)

var now = func() time.Time {
	return time.Now().UTC()
}

// pointer returns the pointer of v.
func pointer[T any](v T) *T {
	return &v
}

// defaultContext returns the default context used in requests to azure.
func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// getKeyName returns the uri of the key vault key.
func getKeyName(vault, name string, key *azkeys.JSONWebKey) string {
	if key != nil && key.KID != nil {
		if u, err := url.Parse(string(*key.KID)); err == nil {
			host := strings.SplitN(u.Host, ".", 2)
			path := strings.Split(u.Path, "/")
			if len(host) == 2 && len(path) == 4 {
				values := url.Values{
					"vault": []string{host[0]},
					"name":  []string{path[2]},
				}
				uu := uri.New(Scheme, values)
				uu.RawQuery = url.Values{"version": []string{path[3]}}.Encode()
				return uu.String()
			}
		}
	}

	// Fallback to URI without version id.
	// This will return the latest version of the key.
	values := url.Values{
		"vault": []string{vault},
		"name":  []string{name},
	}
	return uri.New(Scheme, values).String()
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
func parseKeyName(rawURI string, defaults defaultOptions) (vault, name, version string, hsm bool, err error) {
	var u *uri.URI

	u, err = uri.ParseWithScheme(Scheme, rawURI)
	if err != nil {
		return
	}
	if name = u.Get("name"); name == "" {
		err = errors.Errorf("key uri %q is not valid: name is missing", rawURI)
		return
	}
	if vault = u.Get("vault"); vault == "" {
		if defaults.Vault == "" {
			name = ""
			err = errors.Errorf("key uri %q is not valid: vault is missing", rawURI)
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

	return
}

func convertKey(key *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if key == nil || key.Kty == nil {
		return nil, errors.New("invalid key: missing kty value")
	}

	switch *key.Kty {
	case azkeys.JSONWebKeyTypeEC, azkeys.JSONWebKeyTypeECHSM:
		return ecPublicKey(key.Crv, key.X, key.Y)
	case azkeys.JSONWebKeyTypeRSA, azkeys.JSONWebKeyTypeRSAHSM:
		return rsaPublicKey(key.N, key.E)
	case azkeys.JSONWebKeyTypeOct, azkeys.JSONWebKeyTypeOctHSM:
		return octPublicKey(key.K)
	default:
		return nil, fmt.Errorf("invalid key: unsupported kty %q", *key.Kty)
	}
}

func ecPublicKey(crv *azkeys.JSONWebKeyCurveName, x, y []byte) (crypto.PublicKey, error) {
	if crv == nil {
		return nil, errors.New("invalid EC key: missing crv value")
	}
	if len(x) == 0 || len(y) == 0 {
		return nil, errors.New("invalid EC key: missing x or y values")
	}

	var curve elliptic.Curve
	var curveSize int
	switch *crv {
	case azkeys.JSONWebKeyCurveNameP256:
		curve = elliptic.P256()
		curveSize = 32
	case azkeys.JSONWebKeyCurveNameP384:
		curve = elliptic.P384()
		curveSize = 48
	case azkeys.JSONWebKeyCurveNameP521:
		curve = elliptic.P521()
		curveSize = 66 // (521/8 + 1)
	case azkeys.JSONWebKeyCurveNameP256K:
		return nil, fmt.Errorf(`invalid EC key: crv %q is not supported`, *crv)
	default:
		return nil, fmt.Errorf("invalid EC key: crv %q is not supported", *crv)
	}

	if len(x) != curveSize || len(y) != curveSize {
		return nil, errors.New("invalid EC key: x or y length is not valid")
	}

	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}

	if !curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("invalid EC key: point (x, y) does not lie on the curve")
	}

	return key, nil
}

func rsaPublicKey(n, e []byte) (crypto.PublicKey, error) {
	if len(n) == 0 || len(e) == 0 {
		return nil, errors.New("invalid RSA key: missing n or e values")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}, nil
}

func octPublicKey(k []byte) (crypto.PublicKey, error) {
	if k == nil {
		return nil, errors.New("invalid oct key: missing k value")
	}
	return k, nil
}
