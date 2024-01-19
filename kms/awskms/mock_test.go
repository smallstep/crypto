package awskms

import (
	"context"
	"encoding/pem"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type MockClient struct {
	getPublicKey func(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	createKey    func(ctx context.Context, input *kms.CreateKeyInput, opts ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	createAlias  func(ctx context.Context, input *kms.CreateAliasInput, opts ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	sign         func(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
}

func (m *MockClient) GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return m.getPublicKey(ctx, input, opts...)
}

func (m *MockClient) CreateKey(ctx context.Context, input *kms.CreateKeyInput, opts ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	return m.createKey(ctx, input, opts...)
}

func (m *MockClient) CreateAlias(ctx context.Context, input *kms.CreateAliasInput, opts ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	return m.createAlias(ctx, input, opts...)
}

func (m *MockClient) Sign(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
	return m.sign(ctx, input, opts...)
}

const (
	publicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8XWlIWkOThxNjGbZLYUgRHmsvCrW
KF+HLktPfPTIK3lGd1k4849WQs59XIN+LXZQ6b2eRBEBKAHEyQus8UU7gw==
-----END PUBLIC KEY-----`
	keyID = "be468355-ca7a-40d9-a28b-8ae1c4c7f936"
)

var signature = []byte{
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
}

func getOKClient() *MockClient {
	return &MockClient{
		getPublicKey: func(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			block, _ := pem.Decode([]byte(publicKey))
			return &kms.GetPublicKeyOutput{
				KeyId:     input.KeyId,
				PublicKey: block.Bytes,
			}, nil
		},
		createKey: func(ctx context.Context, input *kms.CreateKeyInput, opts ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
			return &kms.CreateKeyOutput{
				KeyMetadata: &types.KeyMetadata{
					KeyId: pointer(keyID),
				},
			}, nil
		},
		createAlias: func(ctx context.Context, input *kms.CreateAliasInput, opts ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
			return &kms.CreateAliasOutput{}, nil
		},
		sign: func(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error) {
			return &kms.SignOutput{
				Signature: signature,
			}, nil
		},
	}
}
