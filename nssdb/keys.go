package nssdb

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
)

// ASN.1 encoded OID for secp256r1 (1.2.840.10045.3.1.7), the only supported curve.
var ecParams = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

func (obj Object) ToECPublicKey() (*ecdsa.PublicKey, error) {
	if err := obj.ValidateULong("CKA_CLASS", CKO_PUBLIC_KEY); err != nil {
		return nil, err
	}
	if err := obj.ValidateULong("CKA_KEY_TYPE", CKK_EC); err != nil {
		return nil, err
	}
	// TODO(areed) actually parse the params
	if err := obj.Validate("CKA_EC_PARAMS", ecParams); err != nil {
		return nil, err
	}

	ecPointASN1, ok := obj.Attributes["CKA_EC_POINT"]
	if !ok {
		return nil, errors.New("object is missing attribute CKA_EC_POINT")
	}
	var ecPoint []byte
	rest, err := asn1.Unmarshal(ecPointASN1, &ecPoint)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CKA_EC_POINT: %w", err)
	} else if len(rest) > 0 {
		return nil, errors.New("failed to decode CKA_EC_POINT")
	}

	// TODO(areed) parse curve from CKA_EC_PARAMS
	pk, err := ecdh.P256().NewPublicKey(ecPoint)
	if err != nil {
		return nil, fmt.Errorf("parse CKA_EC_POINT: %w", err)
	}
	rawKey := pk.Bytes()

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(rawKey[1:33]),
		Y:     big.NewInt(0).SetBytes(rawKey[33:]),
	}, nil
}

func ecPubKeyToObject(pub *ecdsa.PublicKey, id []byte) (*Object, error) {
	uncompressedPoint := append(append([]byte{0x04}, pub.X.Bytes()...), pub.Y.Bytes()...)
	var b cryptobyte.Builder
	b.AddASN1OctetString(uncompressedPoint)
	ecPoint, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	obj := &Object{
		ULongAttributes: map[string]uint32{
			"CKA_CLASS":    CKO_PUBLIC_KEY,
			"CKA_KEY_TYPE": CKK_EC,
		},
		Attributes: map[string][]byte{
			"CKA_EC_POINT":       ecPoint,
			"CKA_EC_PARAMS":      ecParams,
			"CKA_WRAP":           {0},
			"CKA_LOCAL":          {0},
			"CKA_MODIFIABLE":     {1},
			"CKA_SUBJECT":        {0xa5, 0, 0x5a},
			"CKA_START_DATE":     {0xa5, 0, 0x5a},
			"CKA_END_DATE":       {0xa5, 0, 0x5a},
			"CKA_TOKEN":          {1},
			"CKA_VERIFY":         {1},
			"CKA_VERIFY_RECOVER": {0},
			"CKA_PRIVATE":        {0},
			"CKA_ENCRYPT":        {0},
			"CKA_LABEL":          {0xa5, 0, 0x5a},
			"CKA_DERIVE":         {1},
		},
	}

	if len(id) > 0 {
		obj.Attributes["CKA_ID"] = id
	}

	return obj, nil
}

type certCN struct {
	OID        asn1.ObjectIdentifier
	CommonName string `asn1:"printable"`
}

type privateKeySubject struct {
	List []certCN `asn1:"set"`
}

func ecPrivKeyToObject(priv *ecdsa.PrivateKey, name string, id []byte, certCNs ...string) (*Object, error) {
	pubKey, ok := priv.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get ecdsa public key")
	}
	pubKeyBytes := append(append([]byte{0x04}, pubKey.X.Bytes()...), pubKey.Y.Bytes()...)

	obj := &Object{
		ULongAttributes: map[string]uint32{
			"CKA_CLASS":    CKO_PRIVATE_KEY,
			"CKA_KEY_TYPE": CKK_EC,
		},
		Attributes: map[string][]byte{
			"CKA_VALUE":             priv.D.Bytes(),
			"CKA_UNWRAP":            {0},
			"CKA_SIGN_RECOVER":      {1},
			"CKA_SENSITIVE":         {1},
			"CKA_DECRYPT":           {0},
			"CKA_DERIVE":            {1},
			"CKA_START_DATE":        {0xa5, 0, 0x5a},
			"CKA_END_DATE":          {0xa5, 0, 0x5a},
			"CKA_NEVER_EXTRACTABLE": {0},
			"CKA_EXTRACTABLE":       {1},
			"CKA_MODIFIABLE":        {1},
			"CKA_PRIVATE":           {1},
			"CKA_SIGN":              {1},
			"CKA_LOCAL":             {0},
			"CKA_EC_PARAMS":         ecParams,
			"CKA_NSS_DB":            pubKeyBytes,
			"CKA_TOKEN":             {1},
			"CKA_LABEL":             []byte(name),
			"CKA_ALWAYS_SENSITIVE":  {0},
		},
	}

	if len(certCNs) > 0 {
		sub := privateKeySubject{}
		for _, cn := range certCNs {
			sub.List = append(sub.List, certCN{
				OID:        asn1.ObjectIdentifier{2, 5, 4, 3},
				CommonName: cn,
			})
		}
		subASN1, err := asn1.Marshal(sub)
		if err != nil {
			return nil, fmt.Errorf("marshal CKA_SUBJECT: %w", err)
		}
		obj.Attributes["CKA_SUBJECT"] = subASN1
	}

	if len(id) > 0 {
		obj.Attributes["CKA_ID"] = id
	}

	return obj, nil
}

// AddPrivateKey adds a private key to the nssPrivate database and returns its id.
// The ckaID argument should come from the SubjectKeyID of the associated certificate.
// Keys with the same ckaID will be replaced.
// Only ecdsa keys with curve P-256 are supported.
func (db *NSSDB) AddPrivateKey(ctx context.Context, privKey *ecdsa.PrivateKey, name string, ckaID []byte, certCNs ...string) (uint32, error) {
	if privKey.Curve != elliptic.P256() {
		return 0, errors.New("unsupported curve")
	}

	if len(ckaID) > 0 {
		matches, err := db.findByAttr(ctx, CKO_PRIVATE_KEY, "CKA_ID", ckaID)
		if err != nil {
			return 0, fmt.Errorf("find cka id conflicts: %w", err)
		}
		for _, id := range matches {
			if err := db.DeleteObjectPrivate(ctx, id); err != nil {
				return 0, fmt.Errorf("delete conflicting private key %d: %w", id, err)
			}
		}
	}

	privKeyObj, err := ecPrivKeyToObject(privKey, name, ckaID, certCNs...)
	if err != nil {
		return 0, err
	}

	privKeyID, err := db.InsertPrivate(ctx, privKeyObj)
	if err != nil {
		return 0, err
	}

	return privKeyID, nil
}

// AddPublicKey adds a public key to the nssPublic database and returns its id.
// The ckaID argument should come from the SubjectKeyID of the associated certificate.
// Keys with the same ckaID will be replaced.
// Only ecdsa keys with curve P-256 are supported.
func (db *NSSDB) AddPublicKey(ctx context.Context, pubKey *ecdsa.PublicKey, ckaID []byte) (uint32, error) {
	if pubKey.Curve != elliptic.P256() {
		return 0, errors.New("unsupported curve")
	}

	if len(ckaID) > 0 {
		matches, err := db.findByAttr(ctx, CKO_PUBLIC_KEY, "CKA_ID", ckaID)
		if err != nil {
			return 0, fmt.Errorf("find cka id conflicts: %w", err)
		}
		for _, id := range matches {
			if err := db.DeleteObjectPublic(ctx, id); err != nil {
				return 0, fmt.Errorf("delete conflicting public key %d: %w", id, err)
			}
		}
	}

	pubKeyObj, err := ecPubKeyToObject(pubKey, ckaID)
	if err != nil {
		return 0, err
	}

	pubKeyID, err := db.InsertPublic(ctx, pubKeyObj)
	if err != nil {
		return 0, err
	}

	return pubKeyID, nil
}
