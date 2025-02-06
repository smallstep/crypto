package nssdb

import (
	"context"
	"crypto/x509"
	"database/sql"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObject_AsX509Certificate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		obj := &Object{
			ULongAttributes: map[string]uint32{
				"CKA_CLASS":            CKO_CERTIFICATE,
				"CKA_CERTIFICATE_TYPE": CKC_X_509,
			},
			Attributes: map[string][]byte{
				"CKA_VALUE": leafCrt.Raw,
			},
		}
		got, err := obj.ToX509Certificate()
		require.NoError(t, err)
		assert.True(t, got.Equal(leafCrt))
	})

	t.Run("invalid class", func(t *testing.T) {
		obj := &Object{}
		_, err := obj.ToX509Certificate()
		assert.ErrorContains(t, err, "CKA_CLASS")
	})

	t.Run("invalid certificate type", func(t *testing.T) {
		obj := &Object{
			ULongAttributes: map[string]uint32{
				"CKA_CLASS": CKO_CERTIFICATE,
			},
		}
		_, err := obj.ToX509Certificate()
		assert.ErrorContains(t, err, "CKA_CERTIFICATE_TYPE")
	})

	t.Run("missing CKA_VALUE", func(t *testing.T) {
		obj := &Object{
			ULongAttributes: map[string]uint32{
				"CKA_CLASS":            CKO_CERTIFICATE,
				"CKA_CERTIFICATE_TYPE": CKC_X_509,
			},
		}
		_, err := obj.ToX509Certificate()
		assert.ErrorContains(t, err, "missing attribute CKA_VALUE")
	})

	t.Run("invalid CKA_VALUE", func(t *testing.T) {
		obj := &Object{
			ULongAttributes: map[string]uint32{
				"CKA_CLASS":            CKO_CERTIFICATE,
				"CKA_CERTIFICATE_TYPE": CKC_X_509,
			},
			Attributes: map[string][]byte{
				"CKA_VALUE": {1, 2, 3},
			},
		}
		_, err := obj.ToX509Certificate()
		assert.ErrorContains(t, err, "parse CKA_VALUE")
	})
}

func TestX509CertToObject(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		got, err := x509CertToObject(leafCrt, "My Client Access")
		require.NoError(t, err)
		assert.NoError(t, got.ValidateULong("CKA_CLASS", CKO_CERTIFICATE))
		assert.NoError(t, got.ValidateULong("CKA_CERTIFICATE_TYPE", CKC_X_509))
		assert.Equal(t, []byte("My Client Access"), got.Attributes["CKA_LABEL"])
		assert.Equal(t, leafCrt.Raw, got.Attributes["CKA_VALUE"])
		assert.Equal(t, leafCrt.SubjectKeyId, got.Attributes["CKA_ID"])
		assert.NotEmpty(t, got.Attributes["CKA_SUBJECT"])
		assert.NotEmpty(t, got.Attributes["CKA_ISSUER"])
		assert.NotEmpty(t, got.Attributes["CKA_SERIAL_NUMBER"])
		assert.Equal(t, []byte{0}, got.Attributes["CKA_PRIVATE"])
		assert.Equal(t, []byte{1}, got.Attributes["CKA_MODIFIABLE"])
		assert.Equal(t, []byte{1}, got.Attributes["CKA_TOKEN"])
		assert.Empty(t, got.EncryptedAttributes)
	})

	t.Run("bad serial", func(t *testing.T) {
		_, err := x509CertToObject(&x509.Certificate{}, "x")
		assert.ErrorContains(t, err, "invalid serial number")
	})
}

func TestNSSDB_AddCertificate(t *testing.T) {
	ctx := context.Background()
	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			oldCertObj, err := db.GetObjectPublic(ctx, v.certID)
			require.NoError(t, err)
			oldPubKeyObj, err := db.GetObjectPublic(ctx, v.pubKeyID)
			require.NoError(t, err)
			require.NoError(t, db.Reset(ctx))

			certID, pubKeyID, err := db.AddCertificate(ctx, leafCrt, "leaf")
			require.NoError(t, err)
			assert.NotEmpty(t, certID)
			assert.NotEmpty(t, pubKeyID)

			certObj, err := db.GetObjectPublic(ctx, certID)
			require.NoError(t, err)
			assert.EqualValues(t, CKO_CERTIFICATE, certObj.ULongAttributes["CKA_CLASS"])

			pubKeyObj, err := db.GetObjectPublic(ctx, pubKeyID)
			require.NoError(t, err)
			assert.EqualValues(t, CKO_PUBLIC_KEY, pubKeyObj.ULongAttributes["CKA_CLASS"])

			// verify the certificate imported by this library matches the certificate
			// imported with pk12util in everything besides the id
			oldCertObj.ID = 0
			certObj.ID = 0
			assert.Equal(t, oldCertObj, certObj)

			// verify the public key imported by this library matches the public key
			// imported with pk12util for every attribute except the id
			oldPubKeyObj.ID = 0
			pubKeyObj.ID = 0
			assert.Equal(t, oldPubKeyObj, pubKeyObj)
		})

		t.Run(v.name("ok"), func(t *testing.T) {
			certID, pubKeyID, err := db.AddCertificate(ctx, leafCrt, "name")
			require.NoError(t, err)
			assert.NotEqual(t, v.certID, certID)
			assert.NotEqual(t, v.pubKeyID, pubKeyID)
			_, err = db.GetObjectPublic(ctx, v.certID)
			assert.ErrorIs(t, err, sql.ErrNoRows)
			_, err = db.GetObjectPublic(ctx, v.pubKeyID)
			assert.ErrorIs(t, err, sql.ErrNoRows)
		})
	}
}

func TestNSSDB_Import(t *testing.T) {
	ctx := context.Background()
	for _, v := range nssVersions {
		t.Run(v.name("ok"), func(t *testing.T) {
			db := v.connect(t)
			require.NoError(t, db.Reset(ctx))

			certID, pubKeyID, privKeyID, err := db.Import(ctx, "My Leaf", leafCrt, leafKey)
			require.NoError(t, err)

			certObj, err := db.GetObjectPublic(ctx, certID)
			require.NoError(t, err)
			assert.NoError(t, certObj.ValidateULong("CKA_CLASS", CKO_CERTIFICATE))
			assert.NoError(t, certObj.Validate("CKA_ID", leafCrt.SubjectKeyId))

			pubKeyObj, err := db.GetObjectPublic(ctx, pubKeyID)
			require.NoError(t, err)
			require.NoError(t, err)
			assert.NoError(t, pubKeyObj.ValidateULong("CKA_CLASS", CKO_PUBLIC_KEY))
			assert.NoError(t, pubKeyObj.Validate("CKA_ID", leafCrt.SubjectKeyId))

			privKeyObj, err := db.GetObjectPrivate(ctx, privKeyID)
			require.NoError(t, err)
			require.NoError(t, err)
			assert.NoError(t, privKeyObj.ValidateULong("CKA_CLASS", CKO_PRIVATE_KEY))
			assert.NoError(t, privKeyObj.Validate("CKA_ID", leafCrt.SubjectKeyId))
		})

		// If the nss tools are installed sign some data with pk1sign to validate
		// the imported private key and cert are compatible.
		t.Run(v.name("pk1sign"), func(t *testing.T) {
			p, err := exec.LookPath("pk1sign")
			if err != nil {
				t.Skip("pk1sign not installed")
			}

			db, dir := v.connectDir(t)
			require.NoError(t, db.Reset(ctx))

			_, _, _, err = db.Import(ctx, "leaf", leafCrt, leafKey)
			require.NoError(t, err)

			cmd := exec.Command(p, "-d", dir, "-k", "leaf", "-i", "README.md")
			output, err := cmd.CombinedOutput()
			assert.NoError(t, err, string(output))
		})
	}
}

func TestNSSDB_ListCertificateObjects(t *testing.T) {
	for _, v := range nssVersions {
		db := v.connect(t)

		t.Run(v.name("ok"), func(t *testing.T) {
			objs, err := db.ListCertificateObjects(context.Background())
			require.NoError(t, err)
			assert.Len(t, objs, 1)
			for _, obj := range objs {
				_, err = obj.ToX509Certificate()
				assert.NoError(t, err)
			}
		})
	}
}
