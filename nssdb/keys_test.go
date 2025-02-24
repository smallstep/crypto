package nssdb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/cryptobyte"
)

func TestEcParams(t *testing.T) {
	var b cryptobyte.Builder
	b.AddASN1ObjectIdentifier(p256OID)
	assert.Equal(t, b.BytesOrPanic(), ecParams)
}

func TestObjectToECPublicKey(t *testing.T) {
	// Expecting 67 bytes: 0x04, 0x41, 0x04, (32 bytes of x), (32 bytes of y)
	// The first 0x04 is the ASN1 tag for an octet string, 2nd byte is the length,
	// 3rd byte signals the point is uncompressed
	ecPoint, err := hex.DecodeString("04410485fa4e37fbbb47794c55c2ad22b006d3f8d7bef2aae930279df21ae7f53ffe7d93af484eab694a1e01ff90134a66fbdf2c8d2dbedbd9e7eb9a49374a87a117c7")
	require.NoError(t, err)

	ckaID, err := hex.DecodeString("585b331466d475f55b654deafbd609b58fb5b362")
	require.NoError(t, err)

	obj := Object{
		ULongAttributes: map[string]uint32{
			"CKA_CLASS":    CKO_PUBLIC_KEY,
			"CKA_KEY_TYPE": CKK_EC,
		},
		Attributes: map[string][]byte{
			"CKA_EC_POINT":   ecPoint,
			"CKA_EC_PARAMS":  ecParams,
			"CKA_WRAP":       {0},
			"CKA_LOCAL":      {0},
			"CKA_MODIFIABLE": {1},
			"CKA_SUBJECT":    {0xa5, 0, 0x5a},
			"CKA_END_DATE":   {0xa5, 0, 0x5a},
			"CKA_TOKEN":      {1},
			"CKA_VERIFY":     {1},
			"CKA_PRIVATE":    {0},
			"CKA_ENCRYPT":    {0},
			"CKA_LABEL":      {0xa5, 0, 0x5a},
			"CKA_ID":         ckaID,
		},
	}
	pub, err := obj.ToECPublicKey()
	require.NoError(t, err)
	assert.Equal(t, elliptic.P256(), pub.Curve)
	assert.Equal(t, ecPoint[3:35], pub.X.Bytes())
	assert.Equal(t, ecPoint[35:], pub.Y.Bytes())
}

func TestEcPrivKeyToObject(t *testing.T) {
	privPEM, err := testdata.ReadFile(filepath.Join("testdata", "leaf.key"))
	require.NoError(t, err)
	privKey, err := pemutil.Parse(privPEM)
	require.NoError(t, err)
	ecdsaPrivKey, ok := privKey.(*ecdsa.PrivateKey)
	require.True(t, ok)

	t.Run("printable subject", func(t *testing.T) {
		obj, err := ecPrivKeyToObject(ecdsaPrivKey, "leafkey", []byte{7}, "leaf")
		require.NoError(t, err)
		assert.NoError(t, obj.ValidateULong("CKA_CLASS", CKO_PRIVATE_KEY))
		sub, err := hex.DecodeString("300f310d300b060355040313046c656166")
		require.NoError(t, err)
		assert.NoError(t, obj.Validate("CKA_SUBJECT", sub))
	})

	t.Run("utf8 subject", func(t *testing.T) {
		_, err := ecPrivKeyToObject(ecdsaPrivKey, "leafkey", []byte{7}, "andrew@smallstep.com")
		require.NoError(t, err)
	})
}

func TestNSSDB_AddPrivateKey(t *testing.T) {
	ctx := context.Background()
	for _, v := range nssVersions {
		t.Run(v.name("ok"), func(t *testing.T) {
			db := v.connect(t)
			oldKeyObj, err := db.GetObjectPrivate(ctx, v.privateKeyID)
			require.NoError(t, err)
			certObj, err := db.GetObjectPublic(ctx, v.certID)
			require.NoError(t, err)
			certSubjectKeyID := certObj.Attributes["CKA_ID"]
			require.NoError(t, db.Reset(ctx))

			privKeyID, err := db.AddPrivateKey(ctx, leafKey, "leaf", certSubjectKeyID, "leaf")
			require.NoError(t, err)
			assert.NotEmpty(t, privKeyID)

			privKeyObj, err := db.GetObjectPrivate(ctx, privKeyID)
			require.NoError(t, err)
			assert.EqualValues(t, CKO_PRIVATE_KEY, privKeyObj.ULongAttributes["CKA_CLASS"])
			assert.Len(t, privKeyObj.Metadata, 1)

			// verify the private key imported by this library matches the private key
			// imported with pk12util in everything besides the id, encrypted value and
			// signature
			oldKeyObj.ID = 0
			privKeyObj.ID = 0
			delete(oldKeyObj.EncryptedAttributes, "CKA_VALUE")
			delete(privKeyObj.EncryptedAttributes, "CKA_VALUE")
			oldKeyObj.Metadata = nil
			privKeyObj.Metadata = nil
			assert.Equal(t, oldKeyObj, privKeyObj)
		})

		t.Run(v.name("ok replace"), func(t *testing.T) {
			db := v.connect(t)
			privKeyID, err := db.AddPrivateKey(ctx, leafKey, "leaf", leafCrt.SubjectKeyId, "leaf")
			require.NoError(t, err)
			assert.NotEqual(t, v.privateKeyID, privKeyID)
			_, err = db.GetObjectPrivate(ctx, v.privateKeyID)
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})
	}
}

func TestNSSDB_AddPublicKey(t *testing.T) {
	ctx := context.Background()
	for _, v := range nssVersions {
		t.Run(v.name("ok"), func(t *testing.T) {
			db := v.connect(t)
			oldKeyObj, err := db.GetObjectPublic(ctx, v.pubKeyID)
			require.NoError(t, err)
			require.NoError(t, db.Reset(ctx))

			pubKeyID, err := db.AddPublicKey(ctx, &leafKey.PublicKey, leafCrt.SubjectKeyId)
			require.NoError(t, err)
			assert.NotEmpty(t, pubKeyID)

			pubKeyObj, err := db.GetObjectPublic(ctx, pubKeyID)
			require.NoError(t, err)
			assert.EqualValues(t, CKO_PUBLIC_KEY, pubKeyObj.ULongAttributes["CKA_CLASS"])
			assert.Len(t, pubKeyObj.Metadata, 0)

			// verify the public key imported by this library matches the public key
			// imported with pk12util in everything besides the id
			oldKeyObj.ID = 0
			pubKeyObj.ID = 0
			assert.Equal(t, oldKeyObj, pubKeyObj)
		})

		t.Run(v.name("ok replace"), func(t *testing.T) {
			db := v.connect(t)
			pubKeyID, err := db.AddPublicKey(ctx, &leafKey.PublicKey, leafCrt.SubjectKeyId)
			require.NoError(t, err)
			assert.NotEqual(t, v.pubKeyID, pubKeyID)
			_, err = db.GetObjectPublic(ctx, v.pubKeyID)
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})
	}
}
