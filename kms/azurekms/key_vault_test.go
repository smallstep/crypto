//go:generate mockgen -package mock -mock_names=KeyVaultClient=KeyVaultClient -destination internal/mock/key_vault_client.go go.step.sm/crypto/kms/azurekms KeyVaultClient
package azurekms

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/go-jose/go-jose/v3"
	"github.com/golang/mock/gomock"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/azurekms/internal/mock"
)

var errTest = fmt.Errorf("test error")

func mockNow(t *testing.T) time.Time {
	old := now
	t0 := time.Unix(1234567890, 123).UTC()
	now = func() time.Time {
		return t0
	}
	t.Cleanup(func() {
		now = old
	})
	return t0
}

func mockClient(t *testing.T) *mock.KeyVaultClient {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(func() {
		ctrl.Finish()
	})
	return mock.NewKeyVaultClient(ctrl)
}

type fakeTokenCredential struct{}

func (fakeTokenCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}

func createJWK(t *testing.T, pub crypto.PublicKey) *azkeys.JSONWebKey {
	t.Helper()
	b, err := json.Marshal(&jose.JSONWebKey{
		Key: pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	key := new(azkeys.JSONWebKey)
	if err := json.Unmarshal(b, key); err != nil {
		t.Fatal(err)
	}
	return key
}

func Test_now(t *testing.T) {
	t0 := now()
	if loc := t0.Location(); loc != time.UTC {
		t.Errorf("now() Location = %v, want %v", loc, time.UTC)
	}
}

func TestRegister(t *testing.T) {
	fn, ok := apiv1.LoadKeyManagerNewFunc(apiv1.AzureKMS)
	if !ok {
		t.Fatal("azurekms is not registered")
	}
	k, err := fn(context.Background(), apiv1.Options{
		Type: "azurekms", URI: "azurekms:",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if k == nil {
		t.Fatalf("New() = %v, want &KeyVault{}", k)
	}
}

func TestNew(t *testing.T) {
	old := createCredentials
	t.Cleanup(func() {
		createCredentials = old
	})

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		setup   func()
		args    args
		want    *KeyVault
		wantErr bool
	}{
		{"ok", func() {
			createCredentials = func(ctx context.Context, opts apiv1.Options) (azcore.TokenCredential, error) {
				return fakeTokenCredential{}, nil
			}
		}, args{context.Background(), apiv1.Options{}}, &KeyVault{
			client: newLazyClient("vault.azure.net", lazyClientCreator(fakeTokenCredential{})),
			defaults: defaultOptions{
				DNSSuffix: "vault.azure.net",
			},
		}, false},
		{"ok with vault", func() {
			createCredentials = func(ctx context.Context, opts apiv1.Options) (azcore.TokenCredential, error) {
				return fakeTokenCredential{}, nil
			}
		}, args{context.Background(), apiv1.Options{
			URI: "azurekms:vault=my-vault",
		}}, &KeyVault{
			client: newLazyClient("vault.azure.net", lazyClientCreator(fakeTokenCredential{})),
			defaults: defaultOptions{
				Vault:           "my-vault",
				DNSSuffix:       "vault.azure.net",
				ProtectionLevel: apiv1.UnspecifiedProtectionLevel,
			},
		}, false},
		{"ok with vault + hsm", func() {
			createCredentials = func(ctx context.Context, opts apiv1.Options) (azcore.TokenCredential, error) {
				return fakeTokenCredential{}, nil
			}
		}, args{context.Background(), apiv1.Options{
			URI: "azurekms:vault=my-vault;hsm=true",
		}}, &KeyVault{
			client: newLazyClient("vault.azure.net", lazyClientCreator(fakeTokenCredential{})),
			defaults: defaultOptions{
				Vault:           "my-vault",
				DNSSuffix:       "vault.azure.net",
				ProtectionLevel: apiv1.HSM,
			},
		}, false},
		{"ok with vault + environment", func() {
			createCredentials = func(ctx context.Context, opts apiv1.Options) (azcore.TokenCredential, error) {
				return fakeTokenCredential{}, nil
			}
		}, args{context.Background(), apiv1.Options{
			URI: "azurekms:vault=my-vault;environment=usgov",
		}}, &KeyVault{
			client: newLazyClient("vault.usgovcloudapi.net", lazyClientCreator(fakeTokenCredential{})),
			defaults: defaultOptions{
				Vault:           "my-vault",
				DNSSuffix:       "vault.usgovcloudapi.net",
				ProtectionLevel: apiv1.UnspecifiedProtectionLevel,
			},
		}, false},
		{"fail", func() {
			createCredentials = func(ctx context.Context, opts apiv1.Options) (azcore.TokenCredential, error) {
				return nil, errTest
			}
		}, args{context.Background(), apiv1.Options{}}, nil, true},
		{"fail uri schema", func() {
			createCredentials = func(ctx context.Context, opts apiv1.Options) (azcore.TokenCredential, error) {
				return fakeTokenCredential{}, nil
			}
		}, args{context.Background(), apiv1.Options{
			URI: "kms:vault=my-vault;hsm=true",
		}}, nil, true},
		{"fail uri environment", func() {
			createCredentials = func(ctx context.Context, opts apiv1.Options) (azcore.TokenCredential, error) {
				return fakeTokenCredential{}, nil
			}
		}, args{context.Background(), apiv1.Options{
			URI: "azurekms:environment=bad-one",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want != nil && got != nil {
				got.client = tt.want.client
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_createCredentials(t *testing.T) {
	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{context.Background(), apiv1.Options{}}, false},
		{"ok with uri", args{context.Background(), apiv1.Options{
			URI: "azurekms:client-id=id;client-secret=secret;tenant-id=id",
		}}, false},
		{"ok with uri+aad", args{context.Background(), apiv1.Options{
			URI: "azurekms:client-id=id;client-secret=secret;tenant-id=id;aad-endpoint=https%3A%2F%2Flogin.microsoftonline.us%2F",
		}}, false},
		{"ok with uri+environment", args{context.Background(), apiv1.Options{
			URI: "azurekms:client-id=id;client-secret=secret;tenant-id=id;environment=usgov",
		}}, false},
		{"ok with uri no config", args{context.Background(), apiv1.Options{
			URI: "azurekms:",
		}}, false},
		{"fail uri", args{context.Background(), apiv1.Options{
			URI: "kms:client-id=id;client-secret=secret;tenant-id=id",
		}}, true},
		{"ok bad environment", args{context.Background(), apiv1.Options{
			URI: "azurekms:client-id=id;client-secret=secret;tenant-id=id;environment=fake",
		}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := createCredentials(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKeyVault_GetPublicKey(t *testing.T) {
	key, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	jwk := createJWK(t, pub)

	m := mockClient(t)
	m.EXPECT().GetKey(gomock.Any(), "my-key", "", nil).Return(azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{Key: jwk},
	}, nil)
	m.EXPECT().GetKey(gomock.Any(), "my-key", "my-version", nil).Return(azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{Key: jwk},
	}, nil)
	m.EXPECT().GetKey(gomock.Any(), "my-key", "my-version", nil).Return(azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{Key: jwk},
	}, nil)
	m.EXPECT().GetKey(gomock.Any(), "not-found", "my-version", nil).Return(azkeys.GetKeyResponse{}, errTest)

	client := newLazyClient("vault.azure.net", func(vaultURL string) (KeyVaultClient, error) {
		if vaultURL == "https://fail.vault.azure.net/" {
			return nil, errTest
		}
		return m, nil
	})

	type fields struct {
		client   *lazyClient
		defaults defaultOptions
	}
	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok", fields{client, defaultOptions{}}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=my-vault;name=my-key",
		}}, pub, false},
		{"ok with version", fields{client, defaultOptions{}}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=my-vault;name=my-key?version=my-version",
		}}, pub, false},
		{"ok with options", fields{client, defaultOptions{DNSSuffix: "vault.usgovcloudapi.net"}}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=my-vault;name=my-key?version=my-version",
		}}, pub, false},
		{"fail GetKey", fields{client, defaultOptions{}}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=my-vault;name=not-found?version=my-version",
		}}, nil, true},
		{"fail empty", fields{client, defaultOptions{}}, args{&apiv1.GetPublicKeyRequest{
			Name: "",
		}}, nil, true},
		{"fail vault", fields{client, defaultOptions{}}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=;name=not-found?version=my-version",
		}}, nil, true},
		{"fail id", fields{client, defaultOptions{}}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=;name=?version=my-version",
		}}, nil, true},
		{"fail get client", fields{client, defaultOptions{}}, args{&apiv1.GetPublicKeyRequest{
			Name: "azurekms:vault=fail;name=my-key",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{
				client:   tt.fields.client,
				defaults: tt.fields.defaults,
			}
			got, err := k.GetPublicKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyVault.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_CreateKey(t *testing.T) {
	ecKey, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := keyutil.GenerateSigner("RSA", "", 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecPub := ecKey.Public()
	rsaPub := rsaKey.Public()
	ecJWK := createJWK(t, ecPub)
	rsaJWK := createJWK(t, rsaPub)

	expects := []struct {
		Name    string
		Kty     azkeys.JSONWebKeyType
		KeySize *int32
		Curve   azkeys.JSONWebKeyCurveName
		Key     *azkeys.JSONWebKey
	}{
		{"P-256", azkeys.JSONWebKeyTypeEC, nil, azkeys.JSONWebKeyCurveNameP256, ecJWK},
		{"P-256 HSM", azkeys.JSONWebKeyTypeECHSM, nil, azkeys.JSONWebKeyCurveNameP256, ecJWK},
		{"P-256 HSM (uri)", azkeys.JSONWebKeyTypeECHSM, nil, azkeys.JSONWebKeyCurveNameP256, ecJWK},
		{"P-256 Default", azkeys.JSONWebKeyTypeEC, nil, azkeys.JSONWebKeyCurveNameP256, ecJWK},
		{"P-384", azkeys.JSONWebKeyTypeEC, nil, azkeys.JSONWebKeyCurveNameP384, ecJWK},
		{"P-521", azkeys.JSONWebKeyTypeEC, nil, azkeys.JSONWebKeyCurveNameP521, ecJWK},
		{"RSA 0", azkeys.JSONWebKeyTypeRSA, &value3072, "", rsaJWK},
		{"RSA 0 HSM", azkeys.JSONWebKeyTypeRSAHSM, &value3072, "", rsaJWK},
		{"RSA 0 HSM (uri)", azkeys.JSONWebKeyTypeRSAHSM, &value3072, "", rsaJWK},
		{"RSA 2048", azkeys.JSONWebKeyTypeRSA, &value2048, "", rsaJWK},
		{"RSA 3072", azkeys.JSONWebKeyTypeRSA, &value3072, "", rsaJWK},
		{"RSA 4096", azkeys.JSONWebKeyTypeRSA, &value4096, "", rsaJWK},
	}

	t0 := mockNow(t)
	m := mockClient(t)
	for _, e := range expects {
		m.EXPECT().CreateKey(gomock.Any(), "my-key", azkeys.CreateKeyParameters{
			Kty:     pointer(e.Kty),
			KeySize: e.KeySize,
			Curve:   pointer(e.Curve),
			KeyOps: []*azkeys.JSONWebKeyOperation{
				pointer(azkeys.JSONWebKeyOperationSign),
				pointer(azkeys.JSONWebKeyOperationVerify),
			},
			KeyAttributes: &azkeys.KeyAttributes{
				Enabled:   &valueTrue,
				Created:   &t0,
				NotBefore: &t0,
			},
		}, nil).Return(azkeys.CreateKeyResponse{
			KeyBundle: azkeys.KeyBundle{Key: e.Key},
		}, nil)
	}
	m.EXPECT().CreateKey(gomock.Any(), "not-found", gomock.Any(), nil).Return(azkeys.CreateKeyResponse{}, errTest)
	m.EXPECT().CreateKey(gomock.Any(), "not-found", gomock.Any(), nil).Return(azkeys.CreateKeyResponse{
		KeyBundle: azkeys.KeyBundle{Key: nil},
	}, nil)

	client := newLazyClient("vault.azure.net", func(vaultURL string) (KeyVaultClient, error) {
		if vaultURL == "https://fail.vault.azure.net/" {
			return nil, errTest
		}
		return m, nil
	})

	type fields struct {
		client   *lazyClient
		defaults defaultOptions
	}
	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.CreateKeyResponse
		wantErr bool
	}{
		{"ok P-256", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			ProtectionLevel:    apiv1.Software,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-256 HSM", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			ProtectionLevel:    apiv1.HSM,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-256 HSM (uri)", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key?hsm=true",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-256 Default", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name: "azurekms:vault=my-vault;name=my-key",
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-384", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			SignatureAlgorithm: apiv1.ECDSAWithSHA384,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok P-521", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			SignatureAlgorithm: apiv1.ECDSAWithSHA512,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: ecPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 0", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               0,
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			ProtectionLevel:    apiv1.Software,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 0 HSM", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               0,
			SignatureAlgorithm: apiv1.SHA256WithRSAPSS,
			ProtectionLevel:    apiv1.HSM,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 0 HSM (uri)", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key;hsm=true",
			Bits:               0,
			SignatureAlgorithm: apiv1.SHA256WithRSAPSS,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 2048", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               2048,
			SignatureAlgorithm: apiv1.SHA384WithRSA,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 3072", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               3072,
			SignatureAlgorithm: apiv1.SHA512WithRSA,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"ok RSA 4096", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=my-key",
			Bits:               4096,
			SignatureAlgorithm: apiv1.SHA512WithRSAPSS,
		}}, &apiv1.CreateKeyResponse{
			Name:      "azurekms:name=my-key;vault=my-vault",
			PublicKey: rsaPub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "azurekms:name=my-key;vault=my-vault",
			},
		}, false},
		{"fail createKey", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=not-found",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
		{"fail convertKey", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=not-found",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
		{"fail name", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name: "",
		}}, nil, true},
		{"fail vault", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name: "azurekms:vault=;name=not-found?version=my-version",
		}}, nil, true},
		{"fail id", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name: "azurekms:vault=my-vault;name=?version=my-version",
		}}, nil, true},
		{"fail get client", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=fail;name=my-key",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
			ProtectionLevel:    apiv1.Software,
		}}, nil, true},
		{"fail SignatureAlgorithm", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=not-found",
			SignatureAlgorithm: apiv1.PureEd25519,
		}}, nil, true},
		{"fail bit size", fields{client, defaultOptions{}}, args{&apiv1.CreateKeyRequest{
			Name:               "azurekms:vault=my-vault;name=not-found",
			SignatureAlgorithm: apiv1.SHA384WithRSAPSS,
			Bits:               1024,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{
				client:   tt.fields.client,
				defaults: tt.fields.defaults,
			}
			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyVault.CreateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_CreateSigner(t *testing.T) {
	key, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	jwk := createJWK(t, pub)

	m := mockClient(t)
	m.EXPECT().GetKey(gomock.Any(), "my-key", "", nil).Return(azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{Key: jwk},
	}, nil)
	m.EXPECT().GetKey(gomock.Any(), "my-key", "my-version", nil).Return(azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{Key: jwk},
	}, nil)
	m.EXPECT().GetKey(gomock.Any(), "not-found", "my-version", nil).Return(azkeys.GetKeyResponse{}, errTest)

	client := newLazyClient("vault.azure.net", func(vaultURL string) (KeyVaultClient, error) {
		return m, nil
	})

	type fields struct {
		client *lazyClient
	}
	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"ok", fields{client}, args{&apiv1.CreateSignerRequest{
			SigningKey: "azurekms:vault=my-vault;name=my-key",
		}}, &Signer{
			client:    m,
			name:      "my-key",
			version:   "",
			publicKey: pub,
		}, false},
		{"ok with version", fields{client}, args{&apiv1.CreateSignerRequest{
			SigningKey: "azurekms:vault=my-vault;name=my-key;version=my-version",
		}}, &Signer{
			client:    m,
			name:      "my-key",
			version:   "my-version",
			publicKey: pub,
		}, false},
		{"fail GetKey", fields{client}, args{&apiv1.CreateSignerRequest{
			SigningKey: "azurekms:vault=my-vault;name=not-found;version=my-version",
		}}, nil, true},
		{"fail SigningKey", fields{client}, args{&apiv1.CreateSignerRequest{
			SigningKey: "",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{
				client: tt.fields.client,
			}
			got, err := k.CreateSigner(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyVault.CreateSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_Close(t *testing.T) {
	m := mockClient(t)
	client := newLazyClient("vault.azure.net", func(vaultURL string) (KeyVaultClient, error) {
		return m, nil
	})

	type fields struct {
		client *lazyClient
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{client}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{
				client: tt.fields.client,
			}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_keyType_KeyType(t *testing.T) {
	type fields struct {
		Kty   azkeys.JSONWebKeyType
		Curve azkeys.JSONWebKeyCurveName
	}
	type args struct {
		pl apiv1.ProtectionLevel
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   azkeys.JSONWebKeyType
	}{
		{"ec", fields{azkeys.JSONWebKeyTypeEC, azkeys.JSONWebKeyCurveNameP256}, args{apiv1.UnspecifiedProtectionLevel}, azkeys.JSONWebKeyTypeEC},
		{"ec software", fields{azkeys.JSONWebKeyTypeEC, azkeys.JSONWebKeyCurveNameP384}, args{apiv1.Software}, azkeys.JSONWebKeyTypeEC},
		{"ec hsm", fields{azkeys.JSONWebKeyTypeEC, azkeys.JSONWebKeyCurveNameP521}, args{apiv1.HSM}, azkeys.JSONWebKeyTypeECHSM},
		{"ec hsm type", fields{azkeys.JSONWebKeyTypeECHSM, azkeys.JSONWebKeyCurveNameP521}, args{apiv1.UnspecifiedProtectionLevel}, azkeys.JSONWebKeyTypeECHSM},
		{"rsa", fields{azkeys.JSONWebKeyTypeRSA, azkeys.JSONWebKeyCurveNameP256}, args{apiv1.UnspecifiedProtectionLevel}, azkeys.JSONWebKeyTypeRSA},
		{"rsa software", fields{azkeys.JSONWebKeyTypeRSA, ""}, args{apiv1.Software}, azkeys.JSONWebKeyTypeRSA},
		{"rsa hsm", fields{azkeys.JSONWebKeyTypeRSA, ""}, args{apiv1.HSM}, azkeys.JSONWebKeyTypeRSAHSM},
		{"rsa hsm type", fields{azkeys.JSONWebKeyTypeRSAHSM, ""}, args{apiv1.UnspecifiedProtectionLevel}, azkeys.JSONWebKeyTypeRSAHSM},
		{"empty", fields{"FOO", ""}, args{apiv1.UnspecifiedProtectionLevel}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := keyType{
				Kty:   tt.fields.Kty,
				Curve: tt.fields.Curve,
			}
			if got := k.KeyType(tt.args.pl); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keyType.KeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyVault_ValidateName(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{"azurekms:name=my-key;vault=my-vault"}, false},
		{"ok hsm", args{"azurekms:name=my-key;vault=my-vault?hsm=true"}, false},
		{"fail scheme", args{"azure:name=my-key;vault=my-vault"}, true},
		{"fail parse uri", args{"azurekms:name=%ZZ;vault=my-vault"}, true},
		{"fail no name", args{"azurekms:vault=my-vault"}, true},
		{"fail no vault", args{"azurekms:name=my-key"}, true},
		{"fail empty", args{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KeyVault{}
			if err := k.ValidateName(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("KeyVault.ValidateName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_getCloudConfiguration(t *testing.T) {
	germanCloud := cloud.Configuration{
		ActiveDirectoryAuthorityHost: "https://login.microsoftonline.de/",
		Services:                     map[cloud.ServiceName]cloud.ServiceConfiguration{},
	}

	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    cloudConfiguration
		wantErr bool
	}{
		{"empty", args{""}, cloudConfiguration{Configuration: cloud.AzurePublic, DNSSuffix: "vault.azure.net"}, false},
		{"public", args{"public"}, cloudConfiguration{Configuration: cloud.AzurePublic, DNSSuffix: "vault.azure.net"}, false},
		{"USGov", args{"USGov"}, cloudConfiguration{Configuration: cloud.AzureGovernment, DNSSuffix: "vault.usgovcloudapi.net"}, false},
		{"China", args{"China"}, cloudConfiguration{Configuration: cloud.AzureChina, DNSSuffix: "vault.azure.cn"}, false},
		{"GERMAN", args{"GERMAN"}, cloudConfiguration{Configuration: germanCloud, DNSSuffix: "vault.microsoftazure.de"}, false},
		{"AzurePublicCloud", args{"AzurePublicCloud"}, cloudConfiguration{Configuration: cloud.AzurePublic, DNSSuffix: "vault.azure.net"}, false},
		{"AzureUSGovernmentCloud", args{"AzureUSGovernmentCloud"}, cloudConfiguration{Configuration: cloud.AzureGovernment, DNSSuffix: "vault.usgovcloudapi.net"}, false},
		{"AzureChinaCloud", args{"AzureChinaCloud"}, cloudConfiguration{Configuration: cloud.AzureChina, DNSSuffix: "vault.azure.cn"}, false},
		{"AzureGermanCloud", args{"AzureGermanCloud"}, cloudConfiguration{Configuration: germanCloud, DNSSuffix: "vault.microsoftazure.de"}, false},
		{"fake", args{"fake"}, cloudConfiguration{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCloudConfiguration(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("getCloudConfiguration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCloudConfiguration() = %v, want %v", got, tt.want)
			}
		})
	}
}
