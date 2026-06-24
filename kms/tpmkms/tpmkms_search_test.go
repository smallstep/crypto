package tpmkms

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/x509util"
)

type fakeSearchAK struct {
	name string
	pub  crypto.PublicKey
}

func (f fakeSearchAK) Name() string             { return f.name }
func (f fakeSearchAK) Public() crypto.PublicKey { return f.pub }

type fakeSearchKey struct {
	name       string
	attestedBy string
	signer     crypto.Signer
	signerErr  error
}

func (f fakeSearchKey) Name() string       { return f.name }
func (f fakeSearchKey) AttestedBy() string { return f.attestedBy }
func (f fakeSearchKey) Signer(context.Context) (crypto.Signer, error) {
	if f.signerErr != nil {
		return nil, f.signerErr
	}
	return f.signer, nil
}

func mustSigner(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := keyutil.GenerateKey("EC", "P-256", 0)
	require.NoError(t, err)
	signer, ok := key.(crypto.Signer)
	require.True(t, ok)
	return signer
}

func TestBuildSearchKeysResults(t *testing.T) {
	akSigner := mustSigner(t)
	goodSigner := mustSigner(t)

	t.Run("all loaded", func(t *testing.T) {
		aks := []searchableAK{fakeSearchAK{name: "ak1", pub: akSigner.Public()}}
		keys := []searchableKey{fakeSearchKey{name: "key1", signer: goodSigner}}

		results, errs := buildSearchKeysResults(aks, keys, "")
		assert.Empty(t, errs)
		require.Len(t, results, 2)
		assert.Equal(t, "tpmkms:ak=true;name=ak1", results[0].Name)
		assert.Equal(t, "tpmkms:name=key1", results[1].Name)
		assert.Equal(t, "tpmkms:name=key1", results[1].CreateSignerRequest.SigningKey)
	})

	t.Run("one key fails to load", func(t *testing.T) {
		badErr := errors.New("NTE_BAD_KEYSET")
		keys := []searchableKey{
			fakeSearchKey{name: "good", signer: goodSigner},
			fakeSearchKey{name: "bad", signerErr: badErr},
		}

		results, errs := buildSearchKeysResults(nil, keys, "")

		// the loadable key is still returned...
		require.Len(t, results, 1)
		assert.Equal(t, "tpmkms:name=good", results[0].Name)

		// ...and the failure is reported with the underlying error wrapped and
		// the key it concerns named.
		require.Len(t, errs, 1)
		assert.ErrorIs(t, errs[0], badErr)
		assert.Contains(t, errs[0].Error(), "tpmkms:name=bad")
	})

	t.Run("name filter", func(t *testing.T) {
		keys := []searchableKey{
			fakeSearchKey{name: "wanted", signer: goodSigner},
			fakeSearchKey{name: "other", signer: goodSigner},
		}
		results, errs := buildSearchKeysResults(nil, keys, "wanted")
		assert.Empty(t, errs)
		require.Len(t, results, 1)
		assert.Equal(t, "tpmkms:name=wanted", results[0].Name)
	})

	t.Run("attest-by carried into uri", func(t *testing.T) {
		keys := []searchableKey{fakeSearchKey{name: "key1", attestedBy: "ak1", signer: goodSigner}}
		results, errs := buildSearchKeysResults(nil, keys, "")
		assert.Empty(t, errs)
		require.Len(t, results, 1)
		assert.Equal(t, "tpmkms:attest-by=ak1;name=key1", results[0].Name)
	})
}

func TestTPMKMS_keyNamesBySubjectKeyID(t *testing.T) {
	goodSigner := mustSigner(t)
	goodSKI, err := x509util.GenerateSubjectKeyID(goodSigner.Public())
	require.NoError(t, err)
	goodSKIHex := hex.EncodeToString(goodSKI)

	t.Run("partial: keeps loaded keys, surfaces the failure", func(t *testing.T) {
		badErr := errors.New("NTE_BAD_KEYSET")
		k := &TPMKMS{
			searchKeysFn: func(*apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error) {
				// best-effort: one key loaded, the search also reports a failure.
				return &apiv1.SearchKeysResponse{
					Results: []apiv1.SearchKeyResult{{Name: "tpmkms:name=good", PublicKey: goodSigner.Public()}},
				}, badErr
			},
		}

		m, err := k.keyNamesBySubjectKeyID()

		// the loaded key is mapped...
		require.Len(t, m, 1)
		assert.Equal(t, "tpmkms:name=good", m[goodSKIHex])

		// ...and the failure is surfaced.
		assert.ErrorIs(t, err, badErr)
	})

	t.Run("fatal error is returned as-is", func(t *testing.T) {
		boom := errors.New("boom")
		k := &TPMKMS{
			searchKeysFn: func(*apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error) {
				return nil, boom
			},
		}
		m, err := k.keyNamesBySubjectKeyID()
		assert.Nil(t, m)
		assert.ErrorIs(t, err, boom)
	})

	t.Run("unusable public key folded into error", func(t *testing.T) {
		k := &TPMKMS{
			searchKeysFn: func(*apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error) {
				return &apiv1.SearchKeysResponse{Results: []apiv1.SearchKeyResult{
					{Name: "tpmkms:name=good", PublicKey: goodSigner.Public()},
					{Name: "tpmkms:name=weird", PublicKey: struct{}{}}, // not a real public key
				}}, nil
			},
		}
		m, err := k.keyNamesBySubjectKeyID()

		// the usable key is still mapped.
		require.Len(t, m, 1)
		assert.Equal(t, "tpmkms:name=good", m[goodSKIHex])

		// the unusable one is surfaced as an error, naming the offending key.
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tpmkms:name=weird")
	})
}
