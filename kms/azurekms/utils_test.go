package azurekms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"math/big"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"go.step.sm/crypto/kms/apiv1"
)

func Test_getKeyName(t *testing.T) {
	getBundle := func(kid string) *azkeys.JSONWebKey {
		id := azkeys.ID(kid)
		return &azkeys.JSONWebKey{
			KID: &id,
		}
	}

	type args struct {
		vault  string
		name   string
		bundle *azkeys.JSONWebKey
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok", args{"my-vault", "my-key", getBundle("https://my-vault.vault.azure.net/keys/my-key/my-version")}, "azurekms:name=my-key;vault=my-vault?version=my-version"},
		{"ok usgov", args{"my-vault", "my-key", getBundle("https://my-vault.vault.usgovcloudapi.net/keys/my-key/my-version")}, "azurekms:name=my-key;vault=my-vault?version=my-version"},
		{"ok china", args{"my-vault", "my-key", getBundle("https://my-vault.vault.azure.cn/keys/my-key/my-version")}, "azurekms:name=my-key;vault=my-vault?version=my-version"},
		{"ok german", args{"my-vault", "my-key", getBundle("https://my-vault.vault.microsoftazure.de/keys/my-key/my-version")}, "azurekms:name=my-key;vault=my-vault?version=my-version"},
		{"ok other", args{"my-vault", "my-key", getBundle("https://my-vault.foo.net/keys/my-key/my-version")}, "azurekms:name=my-key;vault=my-vault?version=my-version"},
		{"ok too short", args{"my-vault", "my-key", getBundle("https://my-vault.vault.azure.net/keys/my-version")}, "azurekms:name=my-key;vault=my-vault"},
		{"ok too long", args{"my-vault", "my-key", getBundle("https://my-vault.vault.azure.net/keys/my-key/my-version/sign")}, "azurekms:name=my-key;vault=my-vault"},
		{"ok nil key", args{"my-vault", "my-key", nil}, "azurekms:name=my-key;vault=my-vault"},
		{"ok nil kid", args{"my-vault", "my-key", &azkeys.JSONWebKey{KID: nil}}, "azurekms:name=my-key;vault=my-vault"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getKeyName(tt.args.vault, tt.args.name, tt.args.bundle); got != tt.want {
				t.Errorf("getKeyName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseKeyName(t *testing.T) {
	var noOptions, publicOptions, sovereignOptions defaultOptions
	publicOptions.DNSSuffix = "vault.azure.net"
	sovereignOptions.DNSSuffix = "vault.usgovcloudapi.net"
	type args struct {
		rawURI   string
		defaults defaultOptions
	}
	tests := []struct {
		name        string
		args        args
		wantVault   string
		wantName    string
		wantVersion string
		wantHsm     bool
		wantErr     bool
	}{
		{"ok", args{"azurekms:name=my-key;vault=my-vault?version=my-version", noOptions}, "my-vault", "my-key", "my-version", false, false},
		{"ok opaque version", args{"azurekms:name=my-key;vault=my-vault;version=my-version", publicOptions}, "my-vault", "my-key", "my-version", false, false},
		{"ok no version", args{"azurekms:name=my-key;vault=my-vault", publicOptions}, "my-vault", "my-key", "", false, false},
		{"ok hsm", args{"azurekms:name=my-key;vault=my-vault?hsm=true", sovereignOptions}, "my-vault", "my-key", "", true, false},
		{"ok hsm false", args{"azurekms:name=my-key;vault=my-vault?hsm=false", sovereignOptions}, "my-vault", "my-key", "", false, false},
		{"ok default vault", args{"azurekms:name=my-key?version=my-version", defaultOptions{Vault: "my-vault", DNSSuffix: "vault.azure.net"}}, "my-vault", "my-key", "my-version", false, false},
		{"ok default hsm", args{"azurekms:name=my-key;vault=my-vault?version=my-version", defaultOptions{Vault: "other-vault", ProtectionLevel: apiv1.HSM, DNSSuffix: "vault.azure.net"}}, "my-vault", "my-key", "my-version", true, false},
		{"fail scheme", args{"azure:name=my-key;vault=my-vault", noOptions}, "", "", "", false, true},
		{"fail parse uri", args{"azurekms:name=%ZZ;vault=my-vault", noOptions}, "", "", "", false, true},
		{"fail no name", args{"azurekms:vault=my-vault", noOptions}, "", "", "", false, true},
		{"fail empty name", args{"azurekms:name=;vault=my-vault", noOptions}, "", "", "", false, true},
		{"fail no vault", args{"azurekms:name=my-key", noOptions}, "", "", "", false, true},
		{"fail empty vault", args{"azurekms:name=my-key;vault=", noOptions}, "", "", "", false, true},
		{"fail empty", args{"", noOptions}, "", "", "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVault, gotName, gotVersion, gotHsm, err := parseKeyName(tt.args.rawURI, tt.args.defaults)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKeyName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotVault != tt.wantVault {
				t.Errorf("parseKeyName() gotVault = %v, want %v", gotVault, tt.wantVault)
			}
			if gotName != tt.wantName {
				t.Errorf("parseKeyName() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("parseKeyName() gotVersion = %v, want %v", gotVersion, tt.wantVersion)
			}
			if gotHsm != tt.wantHsm {
				t.Errorf("parseKeyName() gotHsm = %v, want %v", gotHsm, tt.wantHsm)
			}
		})
	}
}

func Test_convertKey(t *testing.T) {
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	encodeXorY := func(i *big.Int, size int) []byte {
		b := i.Bytes()
		if s := size - len(b); s > 0 {
			pad := make([]byte, s)
			//nolint:makezero // prepend with 0s
			return append(pad, b...)
		}
		return b
	}
	encodeE := func(v int) []byte {
		e := make([]byte, 8)
		binary.BigEndian.PutUint64(e, uint64(v))
		return bytes.TrimLeft(e, "\x00")
	}

	// EC Public Key
	x := encodeXorY(p256.X, 32)
	y := encodeXorY(p256.Y, 32)

	// RSA Public key
	n := rsaKey.N.Bytes()
	e := encodeE(rsaKey.E)

	type args struct {
		key *azkeys.JSONWebKey
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok EC P-256", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP256),
			X:   x,
			Y:   y,
		}}, &p256.PublicKey, false},
		{"ok EC P-384", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP384),
			X:   encodeXorY(p384.X, 48),
			Y:   encodeXorY(p384.Y, 48),
		}}, &p384.PublicKey, false},
		{"ok EC P-521", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP521),
			X:   encodeXorY(p521.X, 66),
			Y:   encodeXorY(p521.Y, 66),
		}}, &p521.PublicKey, false},
		{"ok RSA", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeRSA),
			E:   e,
			N:   n,
		}}, &rsaKey.PublicKey, false},
		{"ok EC-HSM", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeECHSM),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP256),
			X:   x,
			Y:   y,
		}}, &p256.PublicKey, false},
		{"ok RSA-HSM", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeRSAHSM),
			E:   e,
			N:   n,
		}}, &rsaKey.PublicKey, false},
		{"ok oct", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeOct),
			K:   []byte("a-symmetric-key"),
		}}, []byte("a-symmetric-key"), false},
		{"fail nil", args{nil}, nil, true},
		{"fail nil kty", args{&azkeys.JSONWebKey{}}, nil, true},
		{"fail kty", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyType("EC-BAD")),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP521),
			X:   encodeXorY(p521.X, 66),
			Y:   encodeXorY(p521.Y, 66),
		}}, nil, true},
		{"fail nil crv", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: nil,
			X:   x,
			Y:   y,
		}}, nil, true},
		{"fail nil x", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP256),
			X:   nil,
			Y:   y,
		}}, nil, true},
		{"fail nil y", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP256),
			X:   x,
			Y:   nil,
		}}, nil, true},
		{"fail size x", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP256),
			X:   encodeXorY(p256.X, 33),
			Y:   y,
		}}, nil, true},
		{"fail size y", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP256),
			X:   x,
			Y:   encodeXorY(p256.Y, 33),
		}}, nil, true},
		{"fail or curve", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP256),
			X:   y,
			Y:   x,
		}}, nil, true},
		{"fail or P-256k", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP256K),
			X:   y,
			Y:   x,
		}}, nil, true},
		{"fail unknown curve", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveName("COOL")),
			X:   y,
			Y:   x,
		}}, nil, true},
		{"fail nil n", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeRSA),
			N:   nil,
			E:   e,
		}}, nil, true},
		{"fail nil e", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeRSA),
			N:   n,
			E:   nil,
		}}, nil, true},
		{"fail nil k", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeOct),
			K:   nil,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertKey(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
