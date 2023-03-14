package azurekms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
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
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// EC Public Key
	x := ecKey.X.Bytes()
	y := ecKey.Y.Bytes()
	pad := make([]byte, 32-len(x))
	x = append(pad, x...)
	pad = make([]byte, 32-len(y))
	y = append(pad, y...)

	// RSA Public key
	n := rsaKey.N.Bytes()
	e := make([]byte, 8)
	binary.BigEndian.PutUint64(e, uint64(rsaKey.E))
	e = bytes.TrimLeft(e, "\x00")

	type args struct {
		key *azkeys.JSONWebKey
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok EC", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeEC),
			Crv: pointer(azkeys.JSONWebKeyCurveNameP256),
			X:   x,
			Y:   y,
		}}, &ecKey.PublicKey, false},
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
		}}, &ecKey.PublicKey, false},
		{"ok RSA-HSM", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeRSAHSM),
			E:   e,
			N:   n,
		}}, &rsaKey.PublicKey, false},
		{"fail unmarshal", args{&azkeys.JSONWebKey{
			Kty: pointer(azkeys.JSONWebKeyTypeOctHSM),
			K:   []byte("the-oct-key"),
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
