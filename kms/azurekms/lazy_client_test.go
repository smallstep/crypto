//go:build !noazurekms

package azurekms

import (
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

func Test_lazyClient_Get(t *testing.T) {
	client := mockClient(t)
	type fields struct {
		clients   map[string]KeyVaultClient
		new       lazyClientFunc
		dnsSuffix string
	}
	type args struct {
		vault string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    KeyVaultClient
		wantErr bool
	}{
		{"ok", fields{map[string]KeyVaultClient{
			"https://test.vault.azure.net/": client,
		}, func(vaultURL string) (KeyVaultClient, error) {
			t.Error("call to new should not happen")
			return client, nil
		}, "vault.azure.net"}, args{"test"}, client, false},
		{"ok new", fields{map[string]KeyVaultClient{}, func(vaultURL string) (KeyVaultClient, error) {
			return client, nil
		}, "vault.azure.net"}, args{"test"}, client, false},
		{"fail", fields{map[string]KeyVaultClient{}, func(vaultURL string) (KeyVaultClient, error) {
			return nil, errTest
		}, "vault.azure.net"}, args{"test"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &lazyClient{
				clients:   tt.fields.clients,
				new:       tt.fields.new,
				dnsSuffix: tt.fields.dnsSuffix,
			}
			got, err := l.Get(tt.args.vault)
			if (err != nil) != tt.wantErr {
				t.Errorf("lazyClient.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("lazyClient.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_lazyClientCreator(t *testing.T) {
	fn := lazyClientCreator(fakeTokenCredential{})
	client, err := fn("https://test.vault.azure.net")
	if err != nil {
		t.Errorf("lazyClientCreator() error = %v", err)
	}
	if _, ok := client.(*azkeys.Client); !ok {
		t.Errorf("lazyClientCreator() = %T, want *azkeys.Client", client)
	}
}
