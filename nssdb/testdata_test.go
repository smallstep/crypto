package nssdb

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"path/filepath"

	"go.step.sm/crypto/pemutil"
)

var (
	encryptedValue             []byte // encoded and encrypted
	encryptedData              []byte // ciphertext before encoding
	encryptedValuePBES2        []byte // encoded pbes2 oid+params
	encryptedValuePBES2Params  []byte // encoded pbes2 container with pbkdf2 and aes256 params
	encryptedValuePBKDF2       []byte // encoded pbkdf2 oid+params
	encryptedValuePBKDF2Params []byte // encoded pbkdf2 params
	encryptedValueSalt         []byte // pbkdf2 salt for the encryptedValue
	encryptedValueIV           []byte // aes256-cbc initialization vector for the encryptedValue
	encryptedValueAES256CBC    []byte // encoded aes256-cbc params
	leafCrt                    *x509.Certificate
	leafKey                    *ecdsa.PrivateKey
)

func init() {
	var err error

	// pkcs5 pbe2 aes-256 cbc encrypted asn1 encoded value
	// Use this link for a visualization, but note the IV is incorrectly shown as a 14-byte octet string
	// https://lapo.it/asn1js/#MIGBMG0GCSqGSIb3DQEFDTBgMEEGCSqGSIb3DQEFDDA0BCAS3JAXH49TGcp-H27_B_zrFeiiVGvIxF1wAFm7Xb-QnAIBAQIBIDAKBggqhkiG9w0CCTAbBglghkgBZQMEASoEDksC-YlVuvYrfHy6EKscBBDpkjW9EqFQAlEWfd7Xe7O4
	encryptedValue, err = hex.DecodeString("308181306d06092a864886f70d01050d3060304106092a864886f70d01050c3034042012dc90171f8f5319ca7e1f6eff07fceb15e8a2546bc8c45d700059bb5dbf909c020101020120300a06082a864886f70d0209301b060960864801650304012a040e4b02f98955baf62b7c7cba10ab1c0410e99235bd12a1500251167dded77bb3b8")
	if err != nil {
		panic(err)
	}

	encryptedValuePBES2 = encryptedValue[3:114]
	encryptedValuePBES2Params = encryptedValue[16:114]
	encryptedValuePBKDF2 = encryptedValue[18:85]
	encryptedValuePBKDF2Params = encryptedValue[31:85]
	encryptedValueSalt = encryptedValue[35:67]
	encryptedValueAES256CBC = encryptedValue[85:114]
	encryptedValueIV = encryptedValue[98:114]
	encryptedData = encryptedValue[116:]

	leafCertPEM, err := testdata.ReadFile(filepath.Join("testdata", "leaf.crt"))
	if err != nil {
		panic(err)
	}
	leafCrt, err = pemutil.ParseCertificate(leafCertPEM)
	if err != nil {
		panic(err)
	}

	keyPEM, err := testdata.ReadFile(filepath.Join("testdata", "leaf.key"))
	if err != nil {
		panic(err)
	}
	privKey, err := pemutil.Parse(keyPEM)
	if err != nil {
		panic(err)
	}
	key, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		panic("private key unexpected type")
	}
	leafKey = key
}

// zero makes invalid strings for testing by changing the nth byte to 0
func zero(in []byte, n int) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	out[n] = 0
	return out
}
