package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"go.step.sm/crypto/pemutil"
)

func TestNewSigner(t *testing.T) {
	okClient := getOKClient()
	key, err := pemutil.ParseKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	type args struct {
		svc        KeyManagementClient
		signingKey string
	}
	tests := []struct {
		name    string
		args    args
		want    *Signer
		wantErr bool
	}{
		{"ok", args{okClient, "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936"}, &Signer{
			client:    okClient,
			keyID:     "be468355-ca7a-40d9-a28b-8ae1c4c7f936",
			publicKey: key,
		}, false},
		{"fail parse", args{okClient, "awskms:key-id="}, nil, true},
		{"fail preload", args{&MockClient{
			getPublicKey: func(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return nil, fmt.Errorf("an error")
			},
		}, "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936"}, nil, true},
		{"fail preload not der", args{&MockClient{
			getPublicKey: func(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
				return &kms.GetPublicKeyOutput{
					KeyId:     input.KeyId,
					PublicKey: []byte(publicKey),
				}, nil
			},
		}, "awskms:key-id=be468355-ca7a-40d9-a28b-8ae1c4c7f936"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.args.svc, tt.args.signingKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Public(t *testing.T) {
	okClient := getOKClient()
	key, err := pemutil.ParseKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		client    KeyManagementClient
		keyID     string
		publicKey crypto.PublicKey
	}
	tests := []struct {
		name   string
		fields fields
		want   crypto.PublicKey
	}{
		{"ok", fields{okClient, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", key}, key},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:    tt.fields.client,
				keyID:     tt.fields.keyID,
				publicKey: tt.fields.publicKey,
			}
			if got := s.Public(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.Public() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Sign(t *testing.T) {
	okClient := getOKClient()
	key, err := pemutil.ParseKey([]byte(publicKey))
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		client    KeyManagementClient
		keyID     string
		publicKey crypto.PublicKey
	}
	type args struct {
		rand   io.Reader
		digest []byte
		opts   crypto.SignerOpts
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok", fields{okClient, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", key}, args{rand.Reader, []byte("digest"), crypto.SHA256}, signature, false},
		{"(raw) ok", fields{okClient, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", key}, args{rand.Reader, []byte("digest"), &AWSOptions{Raw: true, Options: crypto.SHA256}}, signature, false},
		{"fail alg", fields{okClient, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", key}, args{rand.Reader, []byte("digest"), &AWSOptions{Raw: true, Options: crypto.MD5}}, nil, true},
		{"(raw) fail alg", fields{okClient, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", key}, args{rand.Reader, []byte("digest"), crypto.MD5}, nil, true},
		{"fail key", fields{okClient, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", []byte("key")}, args{rand.Reader, []byte("digest"), crypto.SHA256}, nil, true},
		{"fail sign", fields{&MockClient{
			sign: func(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
				return nil, fmt.Errorf("an error")
			},
		}, "be468355-ca7a-40d9-a28b-8ae1c4c7f936", key}, args{rand.Reader, []byte("digest"), crypto.SHA256}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:    tt.fields.client,
				keyID:     tt.fields.keyID,
				publicKey: tt.fields.publicKey,
			}
			got, err := s.Sign(tt.args.rand, tt.args.digest, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Signer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getMessageTypeAndSigningAlgorithm(t *testing.T) {
	type args struct {
		key  crypto.PublicKey
		opts crypto.SignerOpts
	}
	tests := []struct {
		name            string
		args            args
		wantMessageType types.MessageType
		wantAlgo        types.SigningAlgorithmSpec
		wantErr         bool
	}{
		{"rsa+sha256", args{&rsa.PublicKey{}, crypto.SHA256}, types.MessageTypeDigest, "RSASSA_PKCS1_V1_5_SHA_256", false},
		{"rsa+sha384", args{&rsa.PublicKey{}, crypto.SHA384}, types.MessageTypeDigest, "RSASSA_PKCS1_V1_5_SHA_384", false},
		{"rsa+sha512", args{&rsa.PublicKey{}, crypto.SHA512}, types.MessageTypeDigest, "RSASSA_PKCS1_V1_5_SHA_512", false},
		{"pssrsa+sha256", args{&rsa.PublicKey{}, &rsa.PSSOptions{Hash: crypto.SHA256.HashFunc()}}, types.MessageTypeDigest, "RSASSA_PSS_SHA_256", false},
		{"pssrsa+sha384", args{&rsa.PublicKey{}, &rsa.PSSOptions{Hash: crypto.SHA384.HashFunc()}}, types.MessageTypeDigest, "RSASSA_PSS_SHA_384", false},
		{"pssrsa+sha512", args{&rsa.PublicKey{}, &rsa.PSSOptions{Hash: crypto.SHA512.HashFunc()}}, types.MessageTypeDigest, "RSASSA_PSS_SHA_512", false},
		{"P256", args{&ecdsa.PublicKey{}, crypto.SHA256}, types.MessageTypeDigest, "ECDSA_SHA_256", false},
		{"P384", args{&ecdsa.PublicKey{}, crypto.SHA384}, types.MessageTypeDigest, "ECDSA_SHA_384", false},
		{"P521", args{&ecdsa.PublicKey{}, crypto.SHA512}, types.MessageTypeDigest, "ECDSA_SHA_512", false},
		{"(raw)rsa+sha256", args{&rsa.PublicKey{}, &AWSOptions{Raw: true, Options: crypto.SHA256}}, types.MessageTypeRaw, "RSASSA_PKCS1_V1_5_SHA_256", false},
		{"(raw)rsa+sha384", args{&rsa.PublicKey{}, &AWSOptions{Raw: true, Options: crypto.SHA384}}, types.MessageTypeRaw, "RSASSA_PKCS1_V1_5_SHA_384", false},
		{"(raw)rsa+sha512", args{&rsa.PublicKey{}, &AWSOptions{Raw: true, Options: crypto.SHA512}}, types.MessageTypeRaw, "RSASSA_PKCS1_V1_5_SHA_512", false},
		{"(raw)pssrsa+sha256", args{&rsa.PublicKey{}, &AWSOptions{Raw: true, Options: &rsa.PSSOptions{Hash: crypto.SHA256.HashFunc()}}}, types.MessageTypeRaw, "RSASSA_PSS_SHA_256", false},
		{"(raw)pssrsa+sha384", args{&rsa.PublicKey{}, &AWSOptions{Raw: true, Options: &rsa.PSSOptions{Hash: crypto.SHA384.HashFunc()}}}, types.MessageTypeRaw, "RSASSA_PSS_SHA_384", false},
		{"(raw)pssrsa+sha512", args{&rsa.PublicKey{}, &AWSOptions{Raw: true, Options: &rsa.PSSOptions{Hash: crypto.SHA512.HashFunc()}}}, types.MessageTypeRaw, "RSASSA_PSS_SHA_512", false},
		{"(raw)P256", args{&ecdsa.PublicKey{}, &AWSOptions{Raw: true, Options: crypto.SHA256}}, types.MessageTypeRaw, "ECDSA_SHA_256", false},
		{"(raw)P384", args{&ecdsa.PublicKey{}, &AWSOptions{Raw: true, Options: crypto.SHA384}}, types.MessageTypeRaw, "ECDSA_SHA_384", false},
		{"(raw)P521", args{&ecdsa.PublicKey{}, &AWSOptions{Raw: true, Options: crypto.SHA512}}, types.MessageTypeRaw, "ECDSA_SHA_512", false},
		{"fail type", args{[]byte("key"), crypto.SHA256}, types.MessageTypeDigest, "", true},
		{"fail rsa alg", args{&rsa.PublicKey{}, crypto.MD5}, types.MessageTypeDigest, "", true},
		{"fail ecdsa alg", args{&ecdsa.PublicKey{}, crypto.MD5}, types.MessageTypeDigest, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMessageType, gotAlgo, err := getMessageTypeAndSigningAlgorithm(tt.args.key, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("getMessageTypeAndSigningAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotMessageType != tt.wantMessageType {
				t.Errorf("getMessageTypeAndSigningAlgorithm() (message type) = %v, want %v", gotMessageType, tt.wantMessageType)
			}
			if gotAlgo != tt.wantAlgo {
				t.Errorf("getMessageTypeAndSigningAlgorithm() (algorithm) = %v, want %v", gotAlgo, tt.wantAlgo)
			}
		})
	}
}
