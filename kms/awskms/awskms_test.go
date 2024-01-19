package awskms

import (
	"context"
	"crypto"
	"fmt"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

func TestRegister(t *testing.T) {
	fn, ok := apiv1.LoadKeyManagerNewFunc(apiv1.AmazonKMS)
	require.True(t, ok)
	_, err := fn(context.Background(), apiv1.Options{})
	require.NoError(t, err)
}

func TestNew(t *testing.T) {
	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	expected := &KMS{
		client: kms.NewFromConfig(cfg),
	}

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *KMS
		wantErr bool
	}{
		{"ok", args{ctx, apiv1.Options{}}, expected, false},
		{"fail with options", args{ctx, apiv1.Options{
			Region:          "us-east-1",
			Profile:         "smallstep",
			CredentialsFile: "~/aws/missing",
		}}, nil, true},
		{"fail with uri", args{ctx, apiv1.Options{
			URI: "awskms:region=us-east-1;profile=smallstep;credentials-file=/var/run/aws/missing",
		}}, nil, true},
		{"fail bad uri", args{ctx, apiv1.Options{
			URI: "pkcs11:region=us-east-1;profile=smallstep;credentials-file=/var/run/aws/credentials",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				if !reflect.DeepEqual(got, tt.want) { //nolint:govet // variable names match crypto formulae docs
					t.Errorf("New() = %#v, want %#v", got, tt.want)
				}
			} else {
				if got.client == nil {
					t.Errorf("New() = %#v, want %#v", got, tt.want)
				}
			}
		})
	}
}

func TestKMS_GetPublicKey(t *testing.T) {
	okClient := getOKClient()
	key, err := pemutil.ParseKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		client KeyManagementClient
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
		{"ok", fields{okClient}, args{&apiv1.GetPublicKeyRequest{
			Name: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
		}}, key, false},
		{"fail empty", fields{okClient}, args{&apiv1.GetPublicKeyRequest{}}, nil, true},
		{"fail name", fields{okClient}, args{&apiv1.GetPublicKeyRequest{
			Name: "awskms:key-id=",
		}}, nil, true},
		{"fail getPublicKey", fields{&MockClient{
			getPublicKey: func(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return nil, fmt.Errorf("an error")
			},
		}}, args{&apiv1.GetPublicKeyRequest{
			Name: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
		}}, nil, true},
		{"fail not der", fields{&MockClient{
			getPublicKey: func(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return &kms.GetPublicKeyOutput{
					KeyId:     input.KeyId,
					PublicKey: []byte(publicKey),
				}, nil
			},
		}}, args{&apiv1.GetPublicKeyRequest{
			Name: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KMS{
				client: tt.fields.client,
			}
			got, err := k.GetPublicKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KMS.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KMS.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKMS_CreateKey(t *testing.T) {
	okClient := getOKClient()
	key, err := pemutil.ParseKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		client KeyManagementClient
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
		{"ok", fields{okClient}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, &apiv1.CreateKeyResponse{
			Name:      "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			PublicKey: key,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			},
		}, false},
		{"ok rsa", fields{okClient}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               2048,
		}}, &apiv1.CreateKeyResponse{
			Name:      "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			PublicKey: key,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			},
		}, false},
		{"fail empty", fields{okClient}, args{&apiv1.CreateKeyRequest{}}, nil, true},
		{"fail unsupported alg", fields{okClient}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.PureEd25519,
		}}, nil, true},
		{"fail unsupported bits", fields{okClient}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               1234,
		}}, nil, true},
		{"fail createKey", fields{&MockClient{
			createKey: func(ctx context.Context, input *kms.CreateKeyInput, opts ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
				return nil, fmt.Errorf("an error")
			},
			createAlias:  okClient.createAlias,
			getPublicKey: okClient.getPublicKey,
		}}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
		{"fail createAlias", fields{&MockClient{
			createKey: okClient.createKey,
			createAlias: func(ctx context.Context, input *kms.CreateAliasInput, opts ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
				return nil, fmt.Errorf("an error")
			},
			getPublicKey: okClient.getPublicKey,
		}}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
		{"fail getPublicKey", fields{&MockClient{
			createKey:   okClient.createKey,
			createAlias: okClient.createAlias,
			getPublicKey: func(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return nil, fmt.Errorf("an error")
			},
		}}, args{&apiv1.CreateKeyRequest{
			Name:               "root",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KMS{
				client: tt.fields.client,
			}
			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KMS.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KMS.CreateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKMS_CreateSigner(t *testing.T) {
	client := getOKClient()
	key, err := pemutil.ParseKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		client KeyManagementClient
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
			SigningKey: "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936",
		}}, &Signer{
			client:    client,
			keyID:     "be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			publicKey: key,
		}, false},
		{"fail empty", fields{client}, args{&apiv1.CreateSignerRequest{}}, nil, true},
		{"fail preload", fields{client}, args{&apiv1.CreateSignerRequest{}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KMS{
				client: tt.fields.client,
			}
			got, err := k.CreateSigner(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("KMS.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KMS.CreateSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKMS_Close(t *testing.T) {
	type fields struct {
		client KeyManagementClient
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{getOKClient()}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &KMS{
				client: tt.fields.client,
			}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("KMS.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseKeyID(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok uri", args{"awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936"}, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", false},
		{"ok key id", args{"be468355-ca7a-40d9-a28b-8ae1c4c7f936"}, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", false},
		{"ok arn", args{"arn:aws:kms:us-east-1:123456789:key/be468355-ca7a-40d9-a28b-8ae1c4c7f936"}, "arn:aws:kms:us-east-1:123456789:key/be468355-ca7a-40d9-a28b-8ae1c4c7f936", false},
		{"fail parse", args{"awskms:key-id=%ZZ"}, "", true},
		{"fail empty key", args{"awskms:key-id="}, "", true},
		{"fail missing", args{"awskms:foo=bar"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeyID(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKeyID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseKeyID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getCustomerMasterKeySpecMapping(t *testing.T) {
	tmp := customerMasterKeySpecMapping
	t.Cleanup(func() {
		customerMasterKeySpecMapping = tmp
	})

	// Fail type switch
	customerMasterKeySpecMapping[apiv1.SignatureAlgorithm(100)] = "string"

	type args struct {
		alg  apiv1.SignatureAlgorithm
		bits int
	}
	tests := []struct {
		name      string
		args      args
		want      types.KeySpec
		assertion assert.ErrorAssertionFunc
	}{
		{"UnspecifiedSignAlgorithm", args{apiv1.UnspecifiedSignAlgorithm, 0}, types.KeySpecEccNistP256, assert.NoError},
		{"SHA256WithRSA", args{apiv1.SHA256WithRSA, 0}, types.KeySpecRsa3072, assert.NoError},
		{"SHA256WithRSA+2048", args{apiv1.SHA256WithRSA, 2048}, types.KeySpecRsa2048, assert.NoError},
		{"SHA256WithRSA+3072", args{apiv1.SHA256WithRSA, 3072}, types.KeySpecRsa3072, assert.NoError},
		{"SHA256WithRSA+4096", args{apiv1.SHA256WithRSA, 4096}, types.KeySpecRsa4096, assert.NoError},
		{"SHA512WithRSA", args{apiv1.SHA512WithRSA, 0}, types.KeySpecRsa3072, assert.NoError},
		{"SHA512WithRSA+2048", args{apiv1.SHA256WithRSA, 2048}, types.KeySpecRsa2048, assert.NoError},
		{"SHA512WithRSA+3072", args{apiv1.SHA256WithRSA, 3072}, types.KeySpecRsa3072, assert.NoError},
		{"SHA512WithRSA+4096", args{apiv1.SHA256WithRSA, 4096}, types.KeySpecRsa4096, assert.NoError},
		{"SHA256WithRSAPSS", args{apiv1.SHA256WithRSAPSS, 0}, types.KeySpecRsa3072, assert.NoError},
		{"SHA256WithRSAPSS+2048", args{apiv1.SHA256WithRSA, 2048}, types.KeySpecRsa2048, assert.NoError},
		{"SHA256WithRSAPSS+3072", args{apiv1.SHA256WithRSA, 3072}, types.KeySpecRsa3072, assert.NoError},
		{"SHA256WithRSAPSS+4096", args{apiv1.SHA256WithRSA, 4096}, types.KeySpecRsa4096, assert.NoError},
		{"SHA512WithRSAPSS", args{apiv1.SHA512WithRSAPSS, 0}, types.KeySpecRsa3072, assert.NoError},
		{"SHA512WithRSAPSS+2048", args{apiv1.SHA256WithRSA, 2048}, types.KeySpecRsa2048, assert.NoError},
		{"SHA512WithRSAPSS+3072", args{apiv1.SHA256WithRSA, 3072}, types.KeySpecRsa3072, assert.NoError},
		{"SHA512WithRSAPSS+4096", args{apiv1.SHA256WithRSA, 4096}, types.KeySpecRsa4096, assert.NoError},
		{"ECDSAWithSHA256", args{apiv1.ECDSAWithSHA256, 0}, types.KeySpecEccNistP256, assert.NoError},
		{"ECDSAWithSHA384", args{apiv1.ECDSAWithSHA384, 0}, types.KeySpecEccNistP384, assert.NoError},
		{"ECDSAWithSHA512", args{apiv1.ECDSAWithSHA512, 0}, types.KeySpecEccNistP521, assert.NoError},
		{"fail Ed25519", args{apiv1.PureEd25519, 0}, "", assert.Error},
		{"fail type switch", args{apiv1.SignatureAlgorithm(100), 0}, "", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getCustomerMasterKeySpecMapping(tt.args.alg, tt.args.bits)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
