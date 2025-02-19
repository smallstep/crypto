//go:build !noawskms
// +build !noawskms

package awskms

import (
	"context"
	"crypto"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/pemutil"
)

// Scheme is the scheme used in uris, the string "awskms".
const Scheme = string(apiv1.AmazonKMS)

// KMS implements a KMS using AWS Key Management Service.
type KMS struct {
	client KeyManagementClient
}

// KeyManagementClient defines the methods on KeyManagementClient that this
// package will use. This interface will be used for unit testing.
type KeyManagementClient interface {
	GetPublicKey(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	CreateKey(ctx context.Context, input *kms.CreateKeyInput, opts ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	CreateAlias(ctx context.Context, input *kms.CreateAliasInput, opts ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	Sign(ctx context.Context, input *kms.SignInput, opts ...func(*kms.Options)) (*kms.SignOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

// customerMasterKeySpecMapping is a mapping between the step signature algorithm,
// and bits for RSA keys, with awskms CustomerMasterKeySpec.
var customerMasterKeySpecMapping = map[apiv1.SignatureAlgorithm]interface{}{
	apiv1.UnspecifiedSignAlgorithm: types.KeySpecEccNistP256,
	apiv1.SHA256WithRSA: map[int]types.KeySpec{
		0:    types.KeySpecRsa3072,
		2048: types.KeySpecRsa2048,
		3072: types.KeySpecRsa3072,
		4096: types.KeySpecRsa4096,
	},
	apiv1.SHA384WithRSA: map[int]types.KeySpec{
		0:    types.KeySpecRsa3072,
		2048: types.KeySpecRsa2048,
		3072: types.KeySpecRsa3072,
		4096: types.KeySpecRsa4096,
	},
	apiv1.SHA512WithRSA: map[int]types.KeySpec{
		0:    types.KeySpecRsa3072,
		2048: types.KeySpecRsa2048,
		3072: types.KeySpecRsa3072,
		4096: types.KeySpecRsa4096,
	},
	apiv1.SHA256WithRSAPSS: map[int]types.KeySpec{
		0:    types.KeySpecRsa3072,
		2048: types.KeySpecRsa2048,
		3072: types.KeySpecRsa3072,
		4096: types.KeySpecRsa4096,
	},
	apiv1.SHA384WithRSAPSS: map[int]types.KeySpec{
		0:    types.KeySpecRsa3072,
		2048: types.KeySpecRsa2048,
		3072: types.KeySpecRsa3072,
		4096: types.KeySpecRsa4096,
	},
	apiv1.SHA512WithRSAPSS: map[int]types.KeySpec{
		0:    types.KeySpecRsa3072,
		2048: types.KeySpecRsa2048,
		3072: types.KeySpecRsa3072,
		4096: types.KeySpecRsa4096,
	},
	apiv1.ECDSAWithSHA256: types.KeySpecEccNistP256,
	apiv1.ECDSAWithSHA384: types.KeySpecEccNistP384,
	apiv1.ECDSAWithSHA512: types.KeySpecEccNistP521,
}

// New creates a new AWSKMS. By default, clients will be created using the
// credentials in `~/.aws/credentials`, but this can be overridden using the
// CredentialsFile option, the Region and Profile can also be configured as
// options.
//
// AWS clients can also be configured with environment variables, see docs at
// https://aws.github.io/aws-sdk-go-v2/docs/configuring-sdk/ for all the
// options.
func New(ctx context.Context, opts apiv1.Options) (*KMS, error) {
	var configOptions []func(*config.LoadOptions) error

	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, err
		}

		if v := u.Get("profile"); v != "" {
			configOptions = append(configOptions, config.WithSharedConfigProfile(v))
		}
		if v := u.Get("region"); v != "" {
			configOptions = append(configOptions, config.WithRegion(v))
		}
		if v := u.Get("credentials-file"); v != "" {
			configOptions = append(configOptions, config.WithSharedConfigFiles([]string{v}))
		}
	}

	// Deprecated way to set configuration parameters.
	if opts.Region != "" {
		configOptions = append(configOptions, config.WithRegion(opts.Region))
	}
	if opts.Profile != "" {
		configOptions = append(configOptions, config.WithSharedConfigProfile(opts.Profile))
	}
	if opts.CredentialsFile != "" {
		configOptions = append(configOptions, config.WithSharedConfigFiles([]string{opts.CredentialsFile}))
	}

	cfg, err := config.LoadDefaultConfig(ctx, configOptions...)
	if err != nil {
		return nil, errors.Wrap(err, "error loading AWS config")
	}

	return &KMS{
		client: kms.NewFromConfig(cfg),
	}, nil
}

func init() {
	apiv1.Register(apiv1.AmazonKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// GetPublicKey returns a public key from KMS.
func (k *KMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, errors.New("getPublicKey 'name' cannot be empty")
	}

	keyID, err := parseKeyID(req.Name)
	if err != nil {
		return nil, err
	}

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := k.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: &keyID,
	})
	if err != nil {
		return nil, errors.Wrap(err, "awskms GetPublicKey failed")
	}

	return pemutil.ParseDER(resp.PublicKey)
}

// CreateKey generates a new key in KMS and returns the public key version
// of it.
func (k *KMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, errors.New("createKeyRequest 'name' cannot be empty")
	}

	keyName, err := parseName(req.Name)
	if err != nil {
		return nil, err
	}

	keySpec, err := getCustomerMasterKeySpecMapping(req.SignatureAlgorithm, req.Bits)
	if err != nil {
		return nil, err
	}

	tag := types.Tag{
		TagKey:   pointer("name"),
		TagValue: pointer(keyName),
	}

	input := &kms.CreateKeyInput{
		Description: pointer(keyName),
		KeySpec:     keySpec,
		Tags:        []types.Tag{tag},
		KeyUsage:    types.KeyUsageTypeSignVerify,
	}

	ctx, cancel := defaultContext()
	defer cancel()

	resp, err := k.client.CreateKey(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, "awskms CreateKey failed")
	}
	if err := k.createKeyAlias(*resp.KeyMetadata.KeyId, keyName); err != nil {
		return nil, err
	}

	// Create uri for key
	name := uri.New("awskms", url.Values{
		"key-id": []string{*resp.KeyMetadata.KeyId},
	}).String()

	publicKey, err := k.GetPublicKey(&apiv1.GetPublicKeyRequest{
		Name: name,
	})
	if err != nil {
		return nil, err
	}

	// Names uses Amazon Resource Name
	// https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
	return &apiv1.CreateKeyResponse{
		Name:      name,
		PublicKey: publicKey,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: name,
		},
	}, nil
}

func (k *KMS) createKeyAlias(keyID, alias string) error {
	ctx, cancel := defaultContext()
	defer cancel()

	_, err := k.client.CreateAlias(ctx, &kms.CreateAliasInput{
		AliasName:   pointer("alias/" + alias + "-" + keyID[:8]),
		TargetKeyId: pointer(keyID),
	})
	if err != nil {
		return errors.Wrap(err, "awskms CreateAlias failed")
	}
	return nil
}

// CreateSigner creates a new crypto.Signer with a previously configured key.
func (k *KMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, errors.New("createSigner 'signingKey' cannot be empty")
	}
	return NewSigner(k.client, req.SigningKey)
}

// Close closes the connection of the KMS client.
func (k *KMS) Close() error {
	return nil
}

func pointer[T any](v T) *T {
	return &v
}

func defaultContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

// parseKeyID extracts the key-id from an uri.
func parseKeyID(name string) (string, error) {
	name = strings.ToLower(name)
	if strings.HasPrefix(name, "awskms:") || strings.HasPrefix(name, "aws:") {
		u, err := uri.Parse(name)
		if err != nil {
			return "", err
		}
		if k := u.Get("key-id"); k != "" {
			return k, nil
		}
		return "", errors.Errorf("failed to get key-id from %s", name)
	}
	return name, nil
}

// parseName extracts the name from an uri.
func parseName(rawuri string) (string, error) {
	if strings.HasPrefix(rawuri, "awskms:") || strings.HasPrefix(rawuri, "aws:") {
		u, err := uri.Parse(rawuri)
		if err != nil {
			return "", err
		}
		if k := u.Get("name"); k != "" {
			return k, nil
		}
		return "", errors.Errorf("failed to get name from %s", rawuri)
	}
	return rawuri, nil
}

func getCustomerMasterKeySpecMapping(alg apiv1.SignatureAlgorithm, bits int) (types.KeySpec, error) {
	v, ok := customerMasterKeySpecMapping[alg]
	if !ok {
		return "", errors.Errorf("awskms does not support signature algorithm '%s'", alg)
	}

	switch v := v.(type) {
	case types.KeySpec:
		return v, nil
	case map[int]types.KeySpec:
		ks, ok := v[bits]
		if !ok {
			return "", errors.Errorf("awskms does not support signature algorithm '%s' with '%d' bits", alg, bits)
		}
		return ks, nil
	default:
		return "", errors.Errorf("unexpected error: this should not happen")
	}
}
