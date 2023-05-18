package cloudkms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestCloudKMS_CreateDecrypter(t *testing.T) {
	keyName := "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"
	pemBytes, err := os.ReadFile("testdata/rsapub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)
	type fields struct {
		client KeyManagementClient
	}
	type args struct {
		req *apiv1.CreateDecrypterRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.Decrypter
		wantErr bool
	}{
		{"ok", fields{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
			},
		}}, args{&apiv1.CreateDecrypterRequest{DecryptionKey: keyName}}, &Decrypter{client: &MockClient{}, decryptionKey: keyName, publicKey: pk}, false},
		{"fail", fields{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return nil, fmt.Errorf("test error")
			},
		}}, args{&apiv1.CreateDecrypterRequest{DecryptionKey: ""}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &CloudKMS{
				client: tt.fields.client,
			}
			got, err := k.CreateDecrypter(tt.args.req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want.Public(), got.Public())
		})
	}
}

func TestNewDecrypter(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/rsapub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)
	type args struct {
		client        KeyManagementClient
		decryptionKey string
	}
	tests := []struct {
		name    string
		args    args
		want    *Decrypter
		wantErr bool
	}{
		{"ok", args{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{Pem: string(pemBytes)}, nil
			},
		}, "decryptionKey"}, &Decrypter{client: &MockClient{}, decryptionKey: "decryptionKey", publicKey: pk}, false},
		{"fail get public key", args{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return nil, fmt.Errorf("an error")
			},
		}, "decryptionKey"}, nil, true},
		{"fail parse pem", args{&MockClient{
			getPublicKey: func(_ context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
				return &kmspb.PublicKey{Pem: string("bad pem")}, nil
			},
		}, "decryptionKey"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDecrypter(tt.args.client, tt.args.decryptionKey)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want.decryptionKey, got.decryptionKey)
			assert.Equal(t, tt.want.publicKey, pk)
		})
	}
}

func TestDecrypter_Public(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/rsapub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)
	type fields struct {
		client        KeyManagementClient
		decryptionKey string
		publicKey     crypto.PublicKey
	}
	tests := []struct {
		name   string
		fields fields
		want   crypto.PublicKey
	}{
		{"ok", fields{&MockClient{}, "decryptionKey", pk}, pk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Decrypter{
				client:        tt.fields.client,
				decryptionKey: tt.fields.decryptionKey,
				publicKey:     tt.fields.publicKey,
			}
			got := d.Public()
			assert.Equal(t, pk, got)
		})
	}
}

func TestDecrypter_Decrypt(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/rsapub.pem")
	require.NoError(t, err)
	pk, err := pemutil.ParseKey(pemBytes)
	require.NoError(t, err)
	keyName := "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"
	okClient := &MockClient{
		asymmetricDecrypt: func(ctx context.Context, adr *kmspb.AsymmetricDecryptRequest, co ...gax.CallOption) (*kmspb.AsymmetricDecryptResponse, error) {
			return &kmspb.AsymmetricDecryptResponse{Plaintext: []byte("decrypted"), PlaintextCrc32C: wrapperspb.Int64(int64(crc32c([]byte("decrypted")))), VerifiedCiphertextCrc32C: true}, nil
		},
	}
	failClient := &MockClient{
		asymmetricDecrypt: func(ctx context.Context, adr *kmspb.AsymmetricDecryptRequest, co ...gax.CallOption) (*kmspb.AsymmetricDecryptResponse, error) {
			return nil, fmt.Errorf("an error")
		},
	}
	requestCRC32Client := &MockClient{
		asymmetricDecrypt: func(ctx context.Context, adr *kmspb.AsymmetricDecryptRequest, co ...gax.CallOption) (*kmspb.AsymmetricDecryptResponse, error) {
			return &kmspb.AsymmetricDecryptResponse{Plaintext: []byte("decrypted"), PlaintextCrc32C: wrapperspb.Int64(int64(crc32c([]byte("decrypted")))), VerifiedCiphertextCrc32C: false}, nil
		},
	}
	responseCRC32Client := &MockClient{
		asymmetricDecrypt: func(ctx context.Context, adr *kmspb.AsymmetricDecryptRequest, co ...gax.CallOption) (*kmspb.AsymmetricDecryptResponse, error) {
			return &kmspb.AsymmetricDecryptResponse{Plaintext: []byte("decrypted"), PlaintextCrc32C: wrapperspb.Int64(int64(crc32c([]byte("wrong")))), VerifiedCiphertextCrc32C: true}, nil
		},
	}
	var nilOpts *rsa.OAEPOptions
	type fields struct {
		client        KeyManagementClient
		decryptionKey string
		publicKey     crypto.PublicKey
	}
	type args struct {
		rand       io.Reader
		ciphertext []byte
		opts       crypto.DecrypterOpts
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "ok",
			fields: fields{
				client:        okClient,
				decryptionKey: keyName,
				publicKey:     pk,
			},
			args: args{
				rand:       rand.Reader,
				ciphertext: []byte("data"),
				opts: &rsa.OAEPOptions{
					Hash:  crypto.SHA256,
					Label: nil,
				},
			},
			want: []byte("decrypted"),
		},
		{
			name: "ok/nil-opts",
			fields: fields{
				client:        okClient,
				decryptionKey: keyName,
				publicKey:     pk,
			},
			args: args{
				rand:       rand.Reader,
				ciphertext: []byte("data"),
			},
			want: []byte("decrypted"),
		},
		{
			name: "ok/nil-oaep-opts",
			fields: fields{
				client:        okClient,
				decryptionKey: keyName,
				publicKey:     pk,
			},
			args: args{
				rand:       rand.Reader,
				ciphertext: []byte("data"),
				opts:       nilOpts,
			},
			want: []byte("decrypted"),
		},
		{
			name: "fail/label-unsupported",
			fields: fields{
				client:        okClient,
				decryptionKey: keyName,
				publicKey:     pk,
			},
			args: args{
				rand:       rand.Reader,
				ciphertext: []byte("data"),
				opts: &rsa.OAEPOptions{
					Hash:  crypto.SHA256,
					Label: []byte("label"),
				},
			},
			wantErr: true,
		},
		{
			name: "fail/unsupported-hash",
			fields: fields{
				client:        okClient,
				decryptionKey: keyName,
				publicKey:     pk,
			},
			args: args{
				rand:       rand.Reader,
				ciphertext: []byte("data"),
				opts: &rsa.OAEPOptions{
					Hash:  crypto.Hash(1000),
					Label: nil,
				},
			},
			wantErr: true,
		},
		{
			name: "fail/pkcs1v15",
			fields: fields{
				client:        okClient,
				decryptionKey: keyName,
				publicKey:     pk,
			},
			args: args{
				rand:       rand.Reader,
				ciphertext: []byte("data"),
				opts:       &rsa.PKCS1v15DecryptOptions{},
			},
			wantErr: true,
		},
		{
			name: "fail/decrypt-failed",
			fields: fields{
				client:        failClient,
				decryptionKey: keyName,
				publicKey:     pk,
			},
			args: args{
				rand:       rand.Reader,
				ciphertext: []byte("data"),
				opts: &rsa.OAEPOptions{
					Hash:  crypto.SHA256,
					Label: nil,
				},
			},
			wantErr: true,
		},
		{
			name: "fail/request-crc32c-failed",
			fields: fields{
				client:        requestCRC32Client,
				decryptionKey: keyName,
				publicKey:     pk,
			},
			args: args{
				rand:       rand.Reader,
				ciphertext: []byte("data"),
				opts: &rsa.OAEPOptions{
					Hash:  crypto.SHA256,
					Label: nil,
				},
			},
			wantErr: true,
		},
		{
			name: "fail/response-crc32c-failed",
			fields: fields{
				client:        responseCRC32Client,
				decryptionKey: keyName,
				publicKey:     pk,
			},
			args: args{
				rand:       rand.Reader,
				ciphertext: []byte("data"),
				opts: &rsa.OAEPOptions{
					Hash:  crypto.SHA256,
					Label: nil,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Decrypter{
				client:        tt.fields.client,
				decryptionKey: tt.fields.decryptionKey,
				publicKey:     tt.fields.publicKey,
			}
			got, err := d.Decrypt(tt.args.rand, tt.args.ciphertext, tt.args.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_crc32c(t *testing.T) {
	tests := []struct {
		name string
		want uint32
	}{
		{"123456789", 0xe3069283},
		{"The quick brown fox jumps over the lazy dog", 0x22620404},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crc32c([]byte(tt.name)); got != tt.want {
				t.Errorf("crc32c() = %v, want %v", got, tt.want)
			}
		})
	}
}
