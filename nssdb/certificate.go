package nssdb

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
)

// ToX509Certificate converts an Object to an x509 Certificate.
func (obj Object) ToX509Certificate() (*x509.Certificate, error) {
	if err := obj.ValidateULong("CKA_CLASS", CKO_CERTIFICATE); err != nil {
		return nil, err
	}
	if err := obj.ValidateULong("CKA_CERTIFICATE_TYPE", CKC_X_509); err != nil {
		return nil, err
	}
	ckaValue, ok := obj.Attributes["CKA_VALUE"]
	if !ok {
		return nil, errors.New("object is missing attribute CKA_VALUE")
	}
	cert, err := x509.ParseCertificate(ckaValue)
	if err != nil {
		return nil, fmt.Errorf("parse CKA_VALUE as certificate: %w", err)
	}

	return cert, nil
}

func x509CertToObject(cert *x509.Certificate, name string) (*Object, error) {
	if name == "" {
		name = cert.Subject.CommonName
	}
	sub := cert.Subject.ToRDNSequence()
	ckaSubject, err := asn1.Marshal(sub)
	if err != nil {
		return nil, fmt.Errorf("invalid subject: %w", err)
	}
	iss := cert.Issuer.ToRDNSequence()
	ckaIssuer, err := asn1.Marshal(iss)
	if err != nil {
		return nil, fmt.Errorf("invalid issuer: %w", err)
	}
	sn, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("invalid serial number: %w", err)
	}

	obj := &Object{
		ULongAttributes: map[string]uint32{
			"CKA_CLASS":            CKO_CERTIFICATE,
			"CKA_CERTIFICATE_TYPE": CKC_X_509,
		},
		Attributes: map[string][]byte{
			"CKA_SUBJECT":       ckaSubject,
			"CKA_PRIVATE":       {0},
			"CKA_ISSUER":        ckaIssuer,
			"CKA_SERIAL_NUMBER": sn,
			"CKA_MODIFIABLE":    {1},
			"CKA_TOKEN":         {1},
			"CKA_LABEL":         []byte(name),
			"CKA_VALUE":         cert.Raw,
			"CKA_ID":            cert.SubjectKeyId,
		},
	}
	return obj, nil
}

// AddCertificate returns the id of the certificate and public key objects.
// Any certificates or public keys with the same subject key id will be replaced.
// The only supported key type is ECDSA with curve P-256.
func (db *NSSDB) AddCertificate(ctx context.Context, cert *x509.Certificate, name string) (uint32, uint32, error) {
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return 0, 0, errors.New("unsupported public key algorithm")
	}
	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return 0, 0, errors.New("unsupported public key type")
	}

	certObj, err := x509CertToObject(cert, name)
	if err != nil {
		return 0, 0, err
	}

	matches, err := db.findByAttr(ctx, CKO_CERTIFICATE, "CKA_ID", cert.SubjectKeyId)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to find by CKA_ID: %w", err)
	}
	for _, id := range matches {
		if err := db.DeleteCertificate(ctx, id); err != nil {
			return 0, 0, fmt.Errorf("failed to delete conflicting certificate %d: %w", id, err)
		}
	}

	certID, err := db.InsertPublic(ctx, certObj)
	if err != nil {
		return 0, 0, err
	}

	pubKeyID, err := db.AddPublicKey(ctx, pubKey, cert.SubjectKeyId)
	if err != nil {
		db.DeleteObjectPublic(ctx, certID)
		return 0, 0, err
	}

	return certID, pubKeyID, nil
}

// Import returns (cert id, public key id, private key id) on success. The
// certificates subject key id will be added as CKA_ID to all three objects to
// bind them together. All certificate and key objects with the same CKA_ID will
// be replaced. Certificates with the same name and different subject key id
// will not be replaced. Use DeleteCertificateByName for that.
// The only supported key type is ECDSA with curve P-256.
func (db *NSSDB) Import(ctx context.Context, name string, cert *x509.Certificate, privKey crypto.PrivateKey) (uint32, uint32, uint32, error) {
	var privKeyID uint32

	switch pk := privKey.(type) {
	case *ecdsa.PrivateKey:
		id, err := db.AddPrivateKey(ctx, pk, name, cert.SubjectKeyId, cert.Subject.CommonName)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("import private key: %w", err)
		}
		privKeyID = id
	default:
		return 0, 0, 0, fmt.Errorf("unsupported private key type %T", privKey)
	}

	certID, pubKeyID, err := db.AddCertificate(ctx, cert, name)
	if err != nil {
		db.DeleteObjectPrivate(ctx, privKeyID)
		return 0, 0, 0, fmt.Errorf("import certificate: %w", err)
	}

	return certID, pubKeyID, privKeyID, nil
}

// DeleteCertificatesByName deletes all certificates with the given nickname,
// along with their keys.
func (db *NSSDB) DeleteCertificatesByName(ctx context.Context, name string) error {
	ids, err := db.findByAttr(ctx, CKO_CERTIFICATE, "CKA_LABEL", []byte(name))
	if err != nil {
		return fmt.Errorf("find certificates with matching name: %w", err)
	}
	for _, id := range ids {
		if err := db.DeleteCertificate(ctx, id); err != nil {
			return fmt.Errorf("delete certificate %d: %w", id, err)
		}
	}
	return nil
}

// DeleteCertificate deletes a certificate and its keys.
func (db *NSSDB) DeleteCertificate(ctx context.Context, id uint32) error {
	obj, err := db.GetObjectPublic(ctx, id)
	if err != nil {
		return err
	}
	if err := obj.ValidateULong("CKA_CLASS", CKO_CERTIFICATE); err != nil {
		return err
	}
	ckaID := obj.Attributes["CKA_ID"]
	if len(ckaID) > 0 {
		pubKeyIDs, err := db.findByAttr(ctx, CKO_PUBLIC_KEY, "CKA_ID", ckaID)
		if err != nil {
			return fmt.Errorf("find public keys: %w", err)
		}
		for _, id := range pubKeyIDs {
			if err := db.DeleteObjectPublic(ctx, id); err != nil {
				return fmt.Errorf("delete public key %d: %w", id, err)
			}
		}
		privKeyIDs, err := db.findByAttr(ctx, CKO_PRIVATE_KEY, "CKA_ID", ckaID)
		if err != nil {
			return fmt.Errorf("find private keys: %w", err)
		}
		for _, id := range privKeyIDs {
			if err := db.DeleteObjectPrivate(ctx, id); err != nil {
				return fmt.Errorf("delete private key %d: %w", id, err)
			}
		}
	}
	if err := db.DeleteObjectPublic(ctx, id); err != nil {
		return fmt.Errorf("delete certificate object: %w", err)
	}
	return nil
}

// ListCertificateObjects returns all x509 certificate objects from the
// nssPublic table in the cert db.
func (db *NSSDB) ListCertificateObjects(ctx context.Context) ([]*Object, error) {
	// a0 is CKA_CLASS and a80 is CKA_CERTIFICATE_TYPE. Both are ulong.
	certClass := encodeDBUlong(CKO_CERTIFICATE)
	certType := encodeDBUlong(CKC_X_509)
	//nolint:gosec // trusted strings
	q := fmt.Sprintf("SELECT id, %s FROM nssPublic WHERE a0 = ? AND a80 = ?", strings.Join(db.columns, ", "))
	rows, err := db.Cert.QueryContext(ctx, q, certClass, certType)
	if err != nil {
		return nil, err
	}
	return db.scanObjects(ctx, rows, false)
}
