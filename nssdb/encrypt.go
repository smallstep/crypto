package nssdb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	asn1tag "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/pbkdf2"

	"go.step.sm/crypto/internal/utils"
	"go.step.sm/crypto/randutil"
)

var (
	pbes2OID      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	pbkdf2OID     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	pbmac1OID     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	hmacSHA256OID = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	aes256CBCOID  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	p256OID       = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
)

type encryptedDataInfo struct {
	pbes2         *pbes2Params
	encryptedData []byte
}

type pbes2Params struct {
	keyGen     keyer
	encryption crypter
}

type marshaler interface {
	marshal(*cryptobyte.Builder)
}

type crypter interface {
	marshaler
	encrypt(key, plaintext []byte) ([]byte, error)
	decrypt(key, ciphertext []byte) ([]byte, error)
}

type keyer interface {
	marshaler
	key(passKey []byte) ([]byte, error)
}

type pbkdf2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int
	PRF        asn1.ObjectIdentifier
}

type aes256CBCParams struct {
	InitializationVector []byte
}

func (db *NSSDB) encrypt(plaintext []byte) ([]byte, error) {
	kdf, err := newPBKDF2(db.emptyPassword)
	if err != nil {
		return nil, err
	}
	key, err := kdf.key(db.passKey)
	if err != nil {
		return nil, err
	}

	aes256, err := newAES256CBC()
	if err != nil {
		return nil, err
	}
	ciphertext, err := aes256.encrypt(key, plaintext)
	if err != nil {
		return nil, err
	}
	pbes2 := &pbes2Params{
		keyGen:     kdf,
		encryption: aes256,
	}

	return encodeCipherText(ciphertext, pbes2)
}

// encodeCipherText takes raw encrypted data and formats it for storage along
// with the pbes2 keygen (pbkdf2) and encryption (e.g. aes256-cbc) params used
func encodeCipherText(encryptedData []byte, pbes2 *pbes2Params) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
		pbes2.marshal(b)
		b.AddASN1OctetString(encryptedData)
	})
	return b.Bytes()
}

func (db *NSSDB) decrypt(ciphertext []byte) ([]byte, error) {
	edi, err := decodeCipherText(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode cipher text: %w", err)
	}
	key, err := edi.pbes2.keyGen.key(db.passKey)
	if err != nil {
		return nil, fmt.Errorf("generate decryption key: %w", err)
	}
	plaintext, err := edi.pbes2.encryption.decrypt(key, edi.encryptedData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func decodeCipherText(cipherText []byte) (*encryptedDataInfo, error) {
	s := cryptobyte.String(cipherText)
	var inner cryptobyte.String
	if ok := s.ReadASN1(&inner, asn1tag.SEQUENCE); !ok {
		return nil, errors.New("decode cipher text")
	}
	var pbes2 cryptobyte.String
	var encryptedData []byte
	if !inner.ReadASN1(&pbes2, asn1tag.SEQUENCE) {
		return nil, errors.New("decode parameters")
	}
	if !inner.ReadASN1Bytes(&encryptedData, asn1tag.OCTET_STRING) {
		return nil, errors.New("decode encrypted data")
	}
	if !inner.Empty() {
		return nil, errors.New("unprocessed cipher text")
	}

	pbesOID := &asn1.ObjectIdentifier{}
	if !pbes2.ReadASN1ObjectIdentifier(pbesOID) {
		return nil, errors.New("decode pbes2 oid")
	}
	if !pbesOID.Equal(pbes2OID) {
		return nil, errors.New("invalid pbes2 oid")
	}
	p := &pbes2Params{}
	if err := p.unmarshal(pbes2); err != nil {
		return nil, fmt.Errorf("unmarshal pbes2: %w", err)
	}

	edi := &encryptedDataInfo{
		pbes2:         p,
		encryptedData: encryptedData,
	}

	return edi, nil
}

func (p *pbes2Params) marshal(b *cryptobyte.Builder) {
	b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(pbes2OID)
		b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
			p.keyGen.marshal(b)
			p.encryption.marshal(b)
		})
	})
}

func (p *pbes2Params) unmarshal(s cryptobyte.String) error {
	var inner cryptobyte.String
	if !s.ReadASN1(&inner, asn1tag.SEQUENCE) {
		return fmt.Errorf("decode pbes2 parameters")
	}

	var keygenS cryptobyte.String
	var encryptS cryptobyte.String
	if !inner.ReadASN1(&keygenS, asn1tag.SEQUENCE) {
		return fmt.Errorf("decode keygen sequence")
	}
	if !inner.ReadASN1(&encryptS, asn1tag.SEQUENCE) {
		return fmt.Errorf("decode encryption sequence")
	}
	if !inner.Empty() {
		return errors.New("unprocessed bytes in pbes parameter sequence")
	}

	keygenOID := asn1.ObjectIdentifier{}
	if !keygenS.ReadASN1ObjectIdentifier(&keygenOID) {
		return errors.New("decode keygen algorithm")
	}
	switch {
	case keygenOID.Equal(pbkdf2OID):
		k := &pbkdf2Params{}
		if err := k.unmarshal(keygenS); err != nil {
			return fmt.Errorf("unmarshal pbkdf2 parameters: %w", err)
		}
		p.keyGen = k
	default:
		return fmt.Errorf("unsupported keygen algorithm %q", keygenOID)
	}

	encryptionOID := asn1.ObjectIdentifier{}
	if !encryptS.ReadASN1ObjectIdentifier(&encryptionOID) {
		return errors.New("decode encryption algorithm")
	}
	switch {
	case encryptionOID.Equal(aes256CBCOID):
		e := &aes256CBCParams{}
		if err := e.unmarshal(encryptS); err != nil {
			return fmt.Errorf("unmarshal aes256-cbc parameters: %w", err)
		}
		p.encryption = e
	default:
		return fmt.Errorf("unsupported encryption algorithm %q", encryptionOID)
	}

	return nil
}

func newPBKDF2(emptyPassword bool) (*pbkdf2Params, error) {
	// NSS uses 10000 if a password is set and 1 if the password is empty
	iterations := 10000
	if emptyPassword {
		iterations = 1
	}
	salt, err := randutil.Salt(32)
	if err != nil {
		return nil, err
	}
	return &pbkdf2Params{
		Salt:       salt,
		Iterations: iterations,
		KeyLength:  32,
		PRF:        hmacSHA256OID,
	}, nil
}

func (p *pbkdf2Params) key(passKey []byte) ([]byte, error) {
	if !p.PRF.Equal(hmacSHA256OID) {
		return nil, fmt.Errorf("prf must be hmac sha256")
	}

	key := pbkdf2.Key(passKey, p.Salt, p.Iterations, p.KeyLength, sha256.New)

	return key, nil
}

func (p *pbkdf2Params) marshal(b *cryptobyte.Builder) {
	b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(pbkdf2OID)
		b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(p.Salt)
			b.AddASN1Int64(int64(p.Iterations))
			b.AddASN1Int64(int64(p.KeyLength))
			b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(hmacSHA256OID)
			})
		})
	})
}

func (p *pbkdf2Params) unmarshal(s cryptobyte.String) error {
	var inner cryptobyte.String
	if !s.ReadASN1(&inner, asn1tag.SEQUENCE) {
		return errors.New("decode parameters")
	}
	if !inner.ReadASN1Bytes(&p.Salt, asn1tag.OCTET_STRING) {
		return errors.New("decode salt")
	}
	if !inner.ReadASN1Integer(&p.Iterations) {
		return errors.New("decode iterations")
	}
	if !inner.ReadASN1Integer(&p.KeyLength) {
		return errors.New("decode key length")
	}
	var prf cryptobyte.String
	if !inner.ReadASN1(&prf, asn1tag.SEQUENCE) {
		return errors.New("decode pseudorandom function sequence")
	}
	if !prf.ReadASN1ObjectIdentifier(&p.PRF) {
		return errors.New("decode pseudorandom function oid")
	}
	if !inner.Empty() || !prf.Empty() {
		return errors.New("unprocessed data")
	}

	return nil
}

func newAES256CBC() (*aes256CBCParams, error) {
	iv, err := randutil.Bytes(aes.BlockSize)
	if err != nil {
		return nil, err
	}
	// TODO(areed) Every IV that I found in an NSS db that was generated by NSS
	// tools started with these bytes. The first byte is the ASN.1 tag for an octet
	// string and the second is length of 14. The NSS tools fail to decode if the
	// IV doesn't start with these two bytes. This means only the trailing 14 bytes
	// of the IV are unique. Need to determine why NSS does this instead of using
	// an 18 byte ASN.1 encoded octet string with 16 random bytes.
	iv[0] = 0x04
	iv[1] = 0x0E
	return &aes256CBCParams{
		InitializationVector: iv,
	}, nil
}

func (p *aes256CBCParams) encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed creating new AES cipher: %w", err)
	}

	paddedPlaintext, err := cbcPad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed padding plaintext: %w", err)
	}

	ciphertext := make([]byte, len(paddedPlaintext))

	enc := cipher.NewCBCEncrypter(block, p.InitializationVector)
	enc.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, nil
}

func (p *aes256CBCParams) decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dec := cipher.NewCBCDecrypter(block, p.InitializationVector)
	plaintext := make([]byte, len(ciphertext))
	dec.CryptBlocks(plaintext, ciphertext)

	out := cbcUnpad(plaintext)
	if out == nil {
		return nil, errors.New("failed to decrypt")
	}
	return out, nil
}

func (p *aes256CBCParams) marshal(b *cryptobyte.Builder) {
	b.AddASN1(asn1tag.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(aes256CBCOID)
		b.AddBytes(p.InitializationVector)
	})
}

func (p *aes256CBCParams) unmarshal(s cryptobyte.String) error {
	p.InitializationVector = s
	return nil
}

// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/padbuf.c#L17
func cbcPad(plaintext []byte) ([]byte, error) {
	inLen := len(plaintext)

	desLen := (inLen + aes.BlockSize) & ^(aes.BlockSize - 1)

	desPadLen, err := utils.SafeUint8(desLen - inLen)
	if err != nil {
		return nil, fmt.Errorf("conversion to uint8 failed: %w", err)
	}

	for i := inLen; i < desLen; i++ {
		plaintext = append(plaintext, desPadLen)
	}

	return plaintext, nil
}

func cbcUnpad(plaintext []byte) []byte {
	if len(plaintext) == 0 {
		return nil
	}
	padLen := plaintext[len(plaintext)-1]
	unpaddedLen := len(plaintext) - int(padLen)
	if unpaddedLen < 1 {
		return nil
	}
	return plaintext[:unpaddedLen]
}
