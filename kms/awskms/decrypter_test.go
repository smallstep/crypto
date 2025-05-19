package awskms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"hash"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/pemutil"
)

func TestCreateDecrypter(t *testing.T) {
	key, err := pemutil.ParseKey([]byte(rsaPublicKey))
	require.NoError(t, err)
	require.IsType(t, &rsa.PublicKey{}, key)
	rsaKey := key.(*rsa.PublicKey)

	k := &KMS{client: &MockClient{
		getPublicKey: func(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			block, _ := pem.Decode([]byte(rsaPublicKey))
			return &kms.GetPublicKeyOutput{
				KeyId:     input.KeyId,
				PublicKey: block.Bytes,
			}, nil
		},
	}}

	// fail with empty decryption key
	d, err := k.CreateDecrypter(&apiv1.CreateDecrypterRequest{
		DecryptionKey: "",
	})
	require.Error(t, err)
	require.Nil(t, d)

	// expect same public key to be returned
	d, err = k.CreateDecrypter(&apiv1.CreateDecrypterRequest{
		DecryptionKey: "test",
	})
	require.NoError(t, err)
	require.NotNil(t, d)
	require.True(t, rsaKey.Equal(d.Public()))
}

func TestDecrypterDecrypts(t *testing.T) {
	km, pub := createTestKMS(t, 2048)
	fail1024KMS, _ := createTestKMS(t, 1024)

	// prepare encrypted contents
	encSHA256, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte("test"), nil)
	require.NoError(t, err)
	encSHA1, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, []byte("test"), nil)
	require.NoError(t, err)

	// create a decrypter, identified by "test-sha256", and check the public key
	d256, err := km.CreateDecrypter(&apiv1.CreateDecrypterRequest{
		DecryptionKey: "test-sha256",
	})
	require.NoError(t, err)
	require.NotNil(t, d256)
	require.True(t, pub.Equal(d256.Public()))

	// create a decrypter, identified by "test-sha1", and check the public key
	d1, err := km.CreateDecrypter(&apiv1.CreateDecrypterRequest{
		DecryptionKey: "test-sha1",
	})
	require.NoError(t, err)
	require.NotNil(t, d1)
	require.True(t, pub.Equal(d1.Public()))

	t.Run("ok/sha256", func(t *testing.T) {
		// successful decryption using OAEP with SHA-256
		plain, err := d256.Decrypt(nil, encSHA256, &rsa.OAEPOptions{Hash: crypto.SHA256})
		require.NoError(t, err)
		require.Equal(t, []byte("test"), plain)
	})

	t.Run("ok/sha1", func(t *testing.T) {
		// successful decryption using OAEP with SHA-1
		plain, err := d1.Decrypt(nil, encSHA1, &rsa.OAEPOptions{Hash: crypto.SHA1})
		require.NoError(t, err)
		require.Equal(t, []byte("test"), plain)
	})

	t.Run("ok/default-options", func(t *testing.T) {
		// successful decryption, defaulting to OAEP with SHA-256
		plain, err := d256.Decrypt(nil, encSHA256, nil)
		require.NoError(t, err)
		require.Equal(t, []byte("test"), plain)
	})

	t.Run("fail/hash", func(t *testing.T) {
		plain, err := d256.Decrypt(nil, encSHA256, &rsa.OAEPOptions{Hash: crypto.SHA384})
		require.EqualError(t, err, `failed determining decryption algorithm: awskms does not support hash algorithm "SHA-384" with RSA-OAEP`)
		require.Empty(t, plain)
	})

	t.Run("fail/label", func(t *testing.T) {
		plain, err := d256.Decrypt(nil, encSHA256, &rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte{1, 2, 3, 4}})
		require.EqualError(t, err, "failed determining decryption algorithm: awskms does not support RSA-OAEP label")
		require.Empty(t, plain)
	})

	t.Run("fail/hash-mismatch", func(t *testing.T) {
		plain, err := d256.Decrypt(nil, encSHA256, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA384})
		require.EqualError(t, err, `failed determining decryption algorithm: awskms does not support using different algorithms for hashing "SHA-256" and masking "SHA-384"`)
		require.Empty(t, plain)
	})

	t.Run("fail/pkcs15", func(t *testing.T) {
		plain, err := d256.Decrypt(nil, encSHA256, &rsa.PKCS1v15DecryptOptions{})
		require.EqualError(t, err, "failed determining decryption algorithm: awskms does not support PKCS #1 v1.5 decryption")
		require.Empty(t, plain)
	})

	t.Run("fail/invalid-options", func(t *testing.T) {
		plain, err := d256.Decrypt(nil, encSHA256, struct{}{})
		require.EqualError(t, err, "failed determining decryption algorithm: invalid decrypter options type struct {}")
		require.Empty(t, plain)
	})

	t.Run("fail/invalid-key", func(t *testing.T) {
		failingDecrypter, err := fail1024KMS.CreateDecrypter(&apiv1.CreateDecrypterRequest{
			DecryptionKey: "fail",
		})
		require.NoError(t, err)

		_, err = failingDecrypter.Decrypt(nil, nil, nil)
		require.EqualError(t, err, "failed determining decryption algorithm: awskms does not support RSA public key size 1024")
	})
}

func createTestKMS(t *testing.T, bitSize int) (*KMS, *rsa.PublicKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	require.NoError(t, err)

	k := &KMS{client: &MockClient{
		getPublicKey: func(ctx context.Context, input *kms.GetPublicKeyInput, opts ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
			block, _ := pemutil.Serialize(key.Public())
			return &kms.GetPublicKeyOutput{
				KeyId:     input.KeyId,
				PublicKey: block.Bytes,
			}, nil
		},
		decrypt: func(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
			var h hash.Hash
			switch *params.KeyId {
			case "test-sha256":
				if params.EncryptionAlgorithm != "RSAES_OAEP_SHA_256" {
					return nil, fmt.Errorf("invalid encryption algorithm %q", params.EncryptionAlgorithm)
				}
				h = sha256.New()
			case "test-sha1":
				if params.EncryptionAlgorithm != "RSAES_OAEP_SHA_1" {
					return nil, fmt.Errorf("invalid encryption algorithm %q", params.EncryptionAlgorithm)
				}
				h = sha1.New()
			default:
				return nil, fmt.Errorf("invalid key ID %q", *params.KeyId)
			}

			dec, err := rsa.DecryptOAEP(h, nil, key, params.CiphertextBlob, nil)
			if err != nil {
				return nil, err
			}
			return &kms.DecryptOutput{
				KeyId:     params.KeyId,
				Plaintext: dec,
			}, nil
		},
	}}

	return k, &key.PublicKey
}
