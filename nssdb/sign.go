package nssdb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	asn1tag "golang.org/x/crypto/cryptobyte/asn1"
)

type pbmac1Params struct {
	kdf *pbkdf2Params
	mac asn1.ObjectIdentifier
}

func (p *pbmac1Params) marshal(b *cryptobyte.Builder) {
	b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(pbmac1OID)
		b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
			p.kdf.marshal(b)
			b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(p.mac)
			})
		})
	})
}

func (db *NSSDB) sign(objectID uint32, value []byte) (*Metadata, error) {
	pbkdf2, err := newPBKDF2(db.emptyPassword)
	if err != nil {
		return nil, err
	}
	signature, err := pbkdf2.signature(value, db.passKey)
	if err != nil {
		return nil, err
	}
	pbmac1 := &pbmac1Params{
		kdf: pbkdf2,
		mac: hmacSHA256OID,
	}
	encodedSig, err := encodeSignature(signature, pbmac1)
	if err != nil {
		return nil, err
	}
	return &Metadata{
		ID:    keySignatureID(objectID),
		Item1: encodedSig,
	}, nil
}

// Generate the id of the record in the metaData table that holds the signature
// for the CKA_VALUE (0x11) attribute of a private key
// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkdb.c#L290
func keySignatureID(objectID uint32) string {
	id := hex.EncodeToString(encodeDBUlong(objectID))
	return fmt.Sprintf("sig_key_%s_00000011", id)
}

// signature generates the signature for an aes-cbc encrypted attribute that can
// be found in item1 of the metaData table.
// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkpwd.c#L420
// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkpwd.c#L560
// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkpwd.c#L456
func (p *pbkdf2Params) signature(value, passKey []byte) ([]byte, error) {
	key, err := p.key(passKey)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, key)

	// First the object ID is written, but when signing the plaintext CKA_VALUE of
	// an encrypted attribute the object ID is 0, not the id of the object the
	// attribute is taken from.
	if _, err := mac.Write(encodeDBUlong(0)); err != nil {
		return nil, err
	}
	// Then write the attribute type. Only CKA_VALUE (0x11) is supported.
	if _, err := mac.Write(encodeDBUlong(0x11)); err != nil {
		return nil, err
	}
	// Finally write the plaintext attribute value.
	if _, err := mac.Write(value); err != nil {
		return nil, err
	}

	return mac.Sum(nil), nil
}

func encodeSignature(signature []byte, pbmac1 *pbmac1Params) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
		pbmac1.marshal(b)
		b.AddASN1OctetString(signature)
	})
	return b.Bytes()
}
