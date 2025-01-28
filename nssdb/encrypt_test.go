package nssdb

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func TestPbes2Params_marshal(t *testing.T) {
	pbes2 := &pbes2Params{
		keyGen: &pbkdf2Params{
			Salt:       encryptedValueSalt,
			Iterations: 1,
			KeyLength:  32,
			PRF:        hmacSHA256OID,
		},
		encryption: &aes256CBCParams{
			InitializationVector: encryptedValueIV,
		},
	}
	b := &cryptobyte.Builder{}
	pbes2.marshal(b)
	got, err := b.Bytes()
	require.NoError(t, err)
	assert.Equal(t, encryptedValuePBES2, got)
}

func TestPbes2Params_unmarshal(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pbes2 := &pbes2Params{}
		err := pbes2.unmarshal(cryptobyte.String(encryptedValuePBES2Params))
		require.NoError(t, err)

		assert.NotNil(t, pbes2.keyGen)
		pbkdf2, ok := pbes2.keyGen.(*pbkdf2Params)
		require.True(t, ok, "decoded pbes2 keyGen is %T", pbes2.keyGen)
		assert.Equal(t, encryptedValueSalt, pbkdf2.Salt)
		assert.EqualValues(t, 1, pbkdf2.Iterations)
		assert.EqualValues(t, 32, pbkdf2.KeyLength)
		assert.True(t, pbkdf2.PRF.Equal(hmacSHA256OID))

		assert.NotNil(t, pbes2.encryption)
		aes256CBC, ok := pbes2.encryption.(*aes256CBCParams)
		require.True(t, ok, "decoded pbes2 encryption is %T", pbes2.encryption)
		assert.Equal(t, encryptedValueIV, aes256CBC.InitializationVector)
	})

	extraBytes := make([]byte, len(encryptedValuePBES2Params)+1)
	copy(extraBytes, encryptedValuePBES2Params)
	extraBytes[len(encryptedValuePBES2Params)] = 0x00
	extraBytes[1]++ // length prefix

	errors := map[string][]byte{
		"decode pbes2 parameters":                      nil,
		"decode keygen sequence":                       zero(encryptedValuePBES2Params, 2),
		"decode encryption sequence":                   zero(encryptedValuePBES2Params, 69),
		"decode keygen algorithm":                      zero(encryptedValuePBES2Params, 4),
		"unmarshal pbkdf2 parameters":                  zero(encryptedValuePBES2Params, 15),
		"unsupported keygen algorithm":                 zero(encryptedValuePBES2Params, 14),
		"decode encryption algorithm":                  zero(encryptedValuePBES2Params, 71),
		"unsupported encryption algorithm":             zero(encryptedValuePBES2Params, 81),
		"unprocessed bytes in pbes parameter sequence": extraBytes,
	}
	for k, v := range errors {
		t.Run(k, func(t *testing.T) {
			err := new(pbes2Params).unmarshal(v)
			assert.ErrorContains(t, err, k)
		})
	}
}

func TestNewPBKDF2(t *testing.T) {
	t.Run("empty password", func(t *testing.T) {
		pbkdf2, err := newPBKDF2(true)
		require.NoError(t, err)
		assert.Len(t, pbkdf2.Salt, 32)
		assert.Equal(t, pbkdf2.Iterations, 1)
		assert.True(t, pbkdf2.PRF.Equal(hmacSHA256OID))
	})

	t.Run("non-empty password", func(t *testing.T) {
		pbkdf2, err := newPBKDF2(false)
		require.NoError(t, err)
		assert.Equal(t, pbkdf2.Iterations, 10000)
	})
}

func TestPbkdf2Params_key(t *testing.T) {
	passKey, err := hex.DecodeString("94E5632537955DF320D4E307AEEDDCBF0966DA66")
	require.NoError(t, err)
	salt, err := hex.DecodeString("4C76DC94CF849B060FD057816B241053DD737F099D7F43BFBE9AE46F48B46361")
	require.NoError(t, err)
	want, err := hex.DecodeString("97949AA294988B0C95ED0A06A6FB38CCF4E3AC0EED5195B15CB11955620350B1")
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		p, err := newPBKDF2(true)
		require.NoError(t, err)
		p.Salt = salt
		got, err := p.key(passKey)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("unsupported prf", func(t *testing.T) {
		p, err := newPBKDF2(true)
		require.NoError(t, err)
		p.PRF = aes256CBCOID
		_, err = p.key(passKey)
		assert.Error(t, err)
	})
}

func TestPbkdf2Params_marshal(t *testing.T) {
	p, err := newPBKDF2(true)
	require.NoError(t, err)
	p.Salt = encryptedValueSalt
	b := &cryptobyte.Builder{}
	p.marshal(b)
	got, err := b.Bytes()
	require.NoError(t, err)
	assert.Equal(t, encryptedValuePBKDF2, got)
}

func TestPbkdf2Params_unmarshal(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		p := &pbkdf2Params{}
		err := p.unmarshal(encryptedValuePBKDF2Params)
		assert.NoError(t, err)
	})

	errors := map[string][]byte{
		"decode parameters":                     nil,
		"decode salt":                           zero(encryptedValuePBKDF2Params, 2),
		"decode iterations":                     zero(encryptedValuePBKDF2Params, 36),
		"decode key length":                     zero(encryptedValuePBKDF2Params, 39),
		"decode pseudorandom function sequence": zero(encryptedValuePBKDF2Params, 42),
		"decode pseudorandom function oid":      zero(encryptedValuePBKDF2Params, 44),
	}
	for k, v := range errors {
		t.Run(k, func(t *testing.T) {
			err := new(pbkdf2Params).unmarshal(v)
			assert.ErrorContains(t, err, k)
		})
	}
}

func TestNewAES256CBC(t *testing.T) {
	aes, err := newAES256CBC()
	require.NoError(t, err)
	assert.Len(t, aes.InitializationVector, 16)
}

func TestAes256CBCParams_encrypt(t *testing.T) {
	key, err := hex.DecodeString("2a5b298761825d178b1b8244bc1082770b12f028289c15c1bf0607cccc3a0f51")
	require.NoError(t, err)
	plaintext, err := hex.DecodeString("f8d5e637123b2bdad965110e85b1dc4aea0d0d075cdbe982937dae7d9bb43e20")
	require.NoError(t, err)
	iv, err := hex.DecodeString("040E7F78BDA94F72DC1AF7C437C50B8C")
	require.NoError(t, err)
	ciphertext, err := hex.DecodeString("D1C6303C053AB06DCC123B035CA6086B9139632B2FE58E5254364A60AC08939AC8ECBDD17DD08878E43C65E94136B1E6")
	require.NoError(t, err)

	aes256 := &aes256CBCParams{
		InitializationVector: iv,
	}
	gotCiphertext, err := aes256.encrypt(key, plaintext)
	require.NoError(t, err)
	assert.Equal(t, ciphertext, gotCiphertext)

	gotPlaintext, err := aes256.decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, gotPlaintext)
}

func TestAes256CBCParams_marshal(t *testing.T) {
	b := &cryptobyte.Builder{}
	p := &aes256CBCParams{
		InitializationVector: encryptedValueIV,
	}
	p.marshal(b)
	got, err := b.Bytes()
	require.NoError(t, err)
	assert.Equal(t, encryptedValueAES256CBC, got)
}

func TestAes256CBCParams_unmarshal(t *testing.T) {
	p := &aes256CBCParams{}
	err := p.unmarshal(encryptedValueIV)
	assert.NoError(t, err)
	assert.Equal(t, encryptedValueIV, p.InitializationVector)
}

func TestDecodeCipherText(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		edi, err := decodeCipherText(encryptedValue)
		require.NoError(t, err)
		assert.Equal(t, encryptedData, edi.encryptedData)
		assert.Len(t, edi.encryptedData, 16)

		assert.NotNil(t, edi.pbes2.keyGen)
		pbkdf2, ok := edi.pbes2.keyGen.(*pbkdf2Params)
		require.True(t, ok, "decoded pbes2 keyGen is %T", edi.pbes2.keyGen)
		assert.Equal(t, encryptedValueSalt, pbkdf2.Salt)
		assert.EqualValues(t, 1, pbkdf2.Iterations)
		assert.EqualValues(t, 32, pbkdf2.KeyLength)
		assert.Equal(t, "1.2.840.113549.2.9", pbkdf2.PRF.String())

		assert.NotNil(t, edi.pbes2.encryption)
		aes256CBC, ok := edi.pbes2.encryption.(*aes256CBCParams)
		require.True(t, ok, "decoded pbes2 encryption is %T", edi.pbes2.encryption)
		assert.Equal(t, encryptedValueIV, aes256CBC.InitializationVector)
	})

	extraBytes := make([]byte, len(encryptedValue)+1)
	copy(extraBytes, encryptedValue)
	extraBytes[len(encryptedValue)] = 0x00
	extraBytes[2]++ // 2nd byte of length prefix

	errors := map[string][]byte{
		"decode cipher text":      nil,
		"decode parameters":       zero(encryptedValue, 3),
		"decode encrypted data":   zero(encryptedValue, 114),
		"unprocessed cipher text": extraBytes,
		"decode pbes2 oid":        zero(encryptedValue, 5),
		"invalid pbes2 oid":       zero(encryptedValue, 15),
		"unmarshal pbes2":         zero(encryptedValue, 16),
	}
	for k, v := range errors {
		t.Run(k, func(t *testing.T) {
			_, err := decodeCipherText(v)
			assert.ErrorContains(t, err, k)
		})
	}
}

func TestEncodeCipherText(t *testing.T) {
	pbes2 := &pbes2Params{
		keyGen: &pbkdf2Params{
			Salt:       encryptedValueSalt,
			Iterations: 1,
			KeyLength:  32,
			PRF:        hmacSHA256OID,
		},
		encryption: &aes256CBCParams{
			InitializationVector: encryptedValueIV,
		},
	}

	got, err := encodeCipherText(encryptedData, pbes2)
	require.NoError(t, err)
	assert.Equal(t, encryptedValue, got)
}

func TestNSSDB_encrypt(t *testing.T) {
	plain := []byte("plaintext")
	db := &NSSDB{
		passKey:       []byte("passKey"),
		emptyPassword: true,
	}

	encodedCipherText, err := db.encrypt(plain)
	require.NoError(t, err)

	decodedPlainText, err := db.decrypt(encodedCipherText)
	require.NoError(t, err)
	assert.Equal(t, plain, decodedPlainText)
}
