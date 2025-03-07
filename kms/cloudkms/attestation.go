package cloudkms

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/pkg/errors"
	"go.step.sm/crypto/pemutil"
)

// Google Hawksbill Root v1 prod certificate, expires on Jan 1 00:00:00 2030 UTC
const googleHawksbillRoot = `-----BEGIN CERTIFICATE-----
MIIDjTCCAnWgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBoMQswCQYDVQQGEwJVUzEL
MAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdv
b2dsZSBJbmMxHzAdBgNVBAMMFkhhd2tzYmlsbCBSb290IHYxIHByb2QwHhcNMTcw
NzAxMDAwMDAwWhcNMzAwMTAxMDAwMDAwWjBoMQswCQYDVQQGEwJVUzELMAkGA1UE
CAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEzARBgNVBAoMCkdvb2dsZSBJ
bmMxHzAdBgNVBAMMFkhhd2tzYmlsbCBSb290IHYxIHByb2QwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCsLqhiiSGgcJLfsI7Dk00mONulol9rHm2obCyD
1lua+AKg+LAW+1zauZu5i028FSbgDk8vtSBDHDF+XsFnqTbIGV7Ctai2lnaQe1UV
TVMWEPBi1diYGceeDrJpJqPz2aXTcIghrGISeyq+IC4z25uQp7G/D8AResKYqYxN
NqcfZlMIk0s6Eh4aPyvCXYtLl9QXD0GDJ6nz4NmC+Fw31B5d5Kg9WXxDZOYC1zU5
9JXbdxxzeC/EJo1k1AHghto/J8edvTIl5NQ0ahOHKoUZzhhDRsVBioFmymVuwaHO
cXTUsHe3NTkNyeLIfoFpsQQ4XcH9kjO67YXTkdCWeNYw/FYZAgMBAAGjQjBAMA8G
A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBQx6FLf4Un4
Ent8budOkXqXdbyorjANBgkqhkiG9w0BAQsFAAOCAQEAjxKOjnr7WYKoD+a+uAld
F8iOwTrHpFLUDS6sqFyx9FLut8Qlmioy/JE9uima7cjeH3U5VBbRcnTglaDiQTac
+JXCIRApEl9N0bDhoVvFeTzRI8nJdMJCWPobNXV3MHpYsgfgzewh4lFUWQghvscF
325VgSEN0a1hgXcnPr05gd+9kTI9zF3r3vyncyYvzYincGX0NQaz1gJW4brm1W+w
TbWVy8Y0o6c1eZm7v8sHoNSg3vIs6JsnQ8bAXK5i2qO/AXZQu25wH1aPQct8QdGw
x2JBsjEjmWpHuBDAXPCesD5cu9UzzDgcpdwmi7Xidl74kj3f/HgrOeimRdOb8lG5
/A==
-----END CERTIFICATE-----`

// Marvell cavium certificate, expires on Nov 16 13:55:25 2025 UTC
// https://www.marvell.com/content/dam/marvell/en/public-collateral/security-solutions/liquid_security_certificate.zip
const caviumRoot = `-----BEGIN CERTIFICATE-----
MIIDoDCCAogCCQDA6q30NN7cFzANBgkqhkiG9w0BAQsFADCBkTELMAkGA1UEBhMC
VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYD
VQQKDAxDYXZpdW0sIEluYy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYD
VQQDDCFsb2NhbGNhLmxpcXVpZHNlY3VyaXR5LmNhdml1bS5jb20wHhcNMTUxMTE5
MTM1NTI1WhcNMjUxMTE2MTM1NTI1WjCBkTELMAkGA1UEBhMCVVMxEzARBgNVBAgM
CkNhbGlmb3JuaWExETAPBgNVBAcMCFNhbiBKb3NlMRUwEwYDVQQKDAxDYXZpdW0s
IEluYy4xFzAVBgNVBAsMDkxpcXVpZFNlY3VyaXR5MSowKAYDVQQDDCFsb2NhbGNh
LmxpcXVpZHNlY3VyaXR5LmNhdml1bS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDckvqQM4cvZjdyqOLGMTjKJwvfxJOhVqw6pojgUMz10VU7z3Ct
JrwHcESwEDUxUkMxzof55kForURLaVVCjedYauEisnZwwSWkAemp9GREm8iX6BXt
oZ8VDWoO2H0AJiHCM62qJeZVXhm8A/zWG0PyLrCINH0yz9ah6BcwdsZGLvQvkpUN
JhwVMrb9nI9BlRmTWhoot1YSTf7jfibEkc/pN+0Ez30RFaL3MhyIaNJS22+10tny
4sOUTsPEtXKah5mPlHpnrGcB18z5Yxgr0vDNYx+FCPGo95XGrq9NYfNMlwsSeFSr
8D1VQ7HZmipeTB1hQTUQw/K/Rmtw5NiljkYTAgMBAAEwDQYJKoZIhvcNAQELBQAD
ggEBAJjqbFaa3FOXEXcXPX2lCHdcyl8TwOR9f3Rq87MEfb3oeK9FarNkUCdvuGs3
OkAWoFib/9l2F7ZgaNlJqVrwBaOvYuGguQoUpDybqttYUJVLcu9vA9eZA+UCJdhd
P7fCyGMO+G96cnG3GTS1/SrIDU+YCnVElQ0P/73/de+ImoeMkwcqiUi2lsf3vGGR
YXMt/DxUwjXwjIpWCs+37cwbNHAv0VKDOR/jmNf5EZf+sy4x2rJZ1NS6eDZ9RBug
CLaN6ntybV4YlE7jDI9XIOm/tPJULZGLpLolngWVB6qtzn1RjBw1HIqpoXg+9s1g
pLFFinSrEL1fkQR0YZQrJckktPs=
-----END CERTIFICATE-----`

type Attestation struct {
	Valid                  bool
	Generated              bool
	Extractable            bool
	KeyType                string
	Algorithm              string
	Format                 string
	Content                []byte
	CertChain              *AttestationCertChain
	PublicKeyAttributes    []AttestationAttribute
	PrivateKeyAttributes   []AttestationAttribute
	SymmetricKeyAttributes []AttestationAttribute
}

type AttestationCertChain struct {
	ManufacturerRoot          string
	ManufacturerCardCert      string
	ManufacturerPartitionCert string
	OwnerRoot                 string
	OwnerCardCert             string
	OwnerPartitionCert        string
}

type AttestationAttribute struct {
	Type uint32
	Data []byte
}

func (v AttestationAttribute) String() string {
	return fmt.Sprintf("0x%04x: b'%x'", v.Type, v.Data)
}

var cryptoKeyVersionRx = regexp.MustCompile("^projects/([^/]+)/locations/([a-zA-Z0-9_-]{1,63})/keyRings/([a-zA-Z0-9_-]{1,63})/cryptoKeys/([a-zA-Z0-9_-]{1,63})/cryptoKeyVersions/([a-zA-Z0-9_-]{1,63})$")

// VerifyAttestation obtains and validates the attestation from an object in
// CloudHSM.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (k *CloudKMS) VerifyAttestation(ctx context.Context, name string) (*Attestation, error) {
	name = resourceName(name)
	if !cryptoKeyVersionRx.MatchString(name) {
		return nil, fmt.Errorf("resource name must match %q", cryptoKeyVersionRx.String())
	}
	return k.verifyAttestation(ctx, name, caviumRoot, googleHawksbillRoot)
}

func (k *CloudKMS) verifyAttestation(ctx context.Context, name, mfrRootPEM, ownerRootPEM string) (*Attestation, error) {
	kv, err := k.client.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{
		Name: name,
	})
	if err != nil {
		return nil, fmt.Errorf("cloudKMS GetCryptoKeyVersion failed: %w", err)
	}
	if kv.Attestation == nil {
		return nil, errors.New("cloudKMS GetCryptoKeyVersion response does not have an attestation")
	}

	att := kv.Attestation
	switch att.Format {
	case kmspb.KeyOperationAttestation_CAVIUM_V1_COMPRESSED, kmspb.KeyOperationAttestation_CAVIUM_V2_COMPRESSED:
	default:
		return nil, fmt.Errorf("attestation format %q is not supported", att.Format.String())
	}

	r, err := gzip.NewReader(bytes.NewReader(att.Content))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	attestation, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read gzip reader: %w", err)
	}

	// Validate and obtain manufacturer certificate
	mfrRoot, err := pemutil.ParseCertificate([]byte(mfrRootPEM))
	if err != nil {
		return nil, err
	}
	mfrCerts := make([]*x509.Certificate, len(att.CertChains.CaviumCerts))
	for i, s := range att.CertChains.CaviumCerts {
		mfrCerts[i], err = pemutil.ParseCertificate([]byte(s))
		if err != nil {
			return nil, err
		}
	}
	mfrCardCert, err := getIssuedCertificate(mfrRoot, mfrCerts)
	if err != nil {
		return nil, err
	}
	mfrPartitionCert, err := getIssuedCertificate(mfrCardCert, mfrCerts)
	if err != nil {
		return nil, err
	}

	// Validate owner certs
	ownerRoot, err := pemutil.ParseCertificate([]byte(ownerRootPEM))
	if err != nil {
		return nil, err
	}
	// Validate and obtain owner card cert
	ownerCardCerts := make([]*x509.Certificate, len(att.CertChains.GoogleCardCerts))
	for i, s := range att.CertChains.GoogleCardCerts {
		ownerCardCerts[i], err = pemutil.ParseCertificate([]byte(s))
		if err != nil {
			return nil, err
		}
	}
	ownerCardCert, err := getIssuedCertificate(ownerRoot, ownerCardCerts, func(crt *x509.Certificate) bool {
		eq, ok := crt.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if ok && eq.Equal(mfrCardCert) {
			return true
		}
		return false
	})
	if err != nil {
		return nil, err
	}
	// Validate and obtain owner partition certificate
	ownerPartitionCerts := make([]*x509.Certificate, len(att.CertChains.GooglePartitionCerts))
	for i, s := range att.CertChains.GooglePartitionCerts {
		ownerPartitionCerts[i], err = pemutil.ParseCertificate([]byte(s))
		if err != nil {
			return nil, err
		}
	}
	ownerPartitionCert, err := getIssuedCertificate(ownerRoot, ownerPartitionCerts, func(crt *x509.Certificate) bool {
		eq, ok := crt.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if ok && eq.Equal(mfrPartitionCert) {
			return true
		}
		return false
	})
	if err != nil {
		return nil, err
	}

	// Get attestation data and signature
	offset := len(attestation) - 256
	data := attestation[:offset]
	signature := attestation[offset:]

	// Validate with manufacturer certificate
	if err := verifySignature(mfrPartitionCert, data, signature); err != nil {
		return nil, fmt.Errorf("error verifying certificate: %w", err)
	}

	// Validate with google certificate
	if err := verifySignature(ownerPartitionCert, data, signature); err != nil {
		return nil, fmt.Errorf("error verifying certificate: %w", err)
	}

	// Parse attestation attributes
	var pub, priv, sym []AttestationAttribute
	if att.Format == kmspb.KeyOperationAttestation_CAVIUM_V1_COMPRESSED {
		pub, priv, err = parseAttestationV1(data, false)
		if err != nil {
			return nil, fmt.Errorf("error parsing attestation data: %w", err)
		}
	} else {
		pub, priv, err = parseAttestation(data)
		if err != nil {
			return nil, fmt.Errorf("error parsing attestation data: %w", err)
		}
	}

	attributes := priv
	if len(attributes) == 0 {
		attributes = pub
		if isSymmetric(kv.Algorithm) {
			sym = attributes
			pub = nil
		}
	}

	var keyType string
	var keySize uint32
	var extractable, generated bool
	for _, v := range attributes {
		switch v.Type {
		case 0x0100:
			keyType = getKeyType(decodeUint32(v.Data, math.MaxUint32))
		case 0x0121:
			keySize = decodeUint32(v.Data, 0)
		case 0x0162:
			extractable = bytes.Equal([]byte{0x01}, v.Data)
		case 0x0163:
			generated = bytes.Equal([]byte{0x01}, v.Data)
		}
	}

	if keyType == "RSA" && keySize > 0 {
		keyType = "RSA " + strconv.FormatUint(uint64(keySize), 10)
	}

	return &Attestation{
		Valid:       true,
		Extractable: extractable,
		Generated:   generated,
		KeyType:     keyType,
		Algorithm:   kv.Algorithm.String(),
		Format:      att.Format.String(),
		Content:     att.Content,
		CertChain: &AttestationCertChain{
			ManufacturerRoot:          caviumRoot,
			ManufacturerCardCert:      serializeCertificate(mfrCardCert),
			ManufacturerPartitionCert: serializeCertificate(mfrPartitionCert),
			OwnerRoot:                 googleHawksbillRoot,
			OwnerCardCert:             serializeCertificate(ownerCardCert),
			OwnerPartitionCert:        serializeCertificate(ownerPartitionCert),
		},
		PublicKeyAttributes:    pub,
		PrivateKeyAttributes:   priv,
		SymmetricKeyAttributes: sym,
	}, nil
}

func getIssuedCertificate(issuer *x509.Certificate, certs []*x509.Certificate, validators ...func(*x509.Certificate) bool) (*x509.Certificate, error) {
	roots := x509.NewCertPool()
	roots.AddCert(issuer)

	for _, crt := range certs {
		if issuer.Equal(crt) {
			continue
		}
		if _, err := crt.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err == nil {
			for _, fn := range validators {
				if !fn(crt) {
					continue
				}
			}
			return crt, nil
		}
	}

	return nil, errors.New("cannot find issued certificate")
}

func verifySignature(crt *x509.Certificate, data, signature []byte) error {
	switch key := crt.PublicKey.(type) {
	case *rsa.PublicKey:
		hashed := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature)
	case *ecdsa.PublicKey:
		var h crypto.Hash
		switch key.Curve {
		case elliptic.P256():
			h = crypto.SHA256
		case elliptic.P384():
			h = crypto.SHA384
		case elliptic.P521():
			h = crypto.SHA512
		default:
			return fmt.Errorf("unsupported elliptic curve")
		}
		hash := h.New()
		hash.Write(data)
		sum := hash.Sum(nil)
		if !ecdsa.VerifyASN1(key, sum, signature) {
			return fmt.Errorf("ecdsa verification error")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type %T", key)
	}
}

func serializeCertificate(crt *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: crt.Raw,
	}))
}

// parseAttestation parses attestation data using the Version 2 format. This
// code is based on the code of parse_v2.py from
// https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/software-key-attestation.html
func parseAttestation(data []byte) ([]AttestationAttribute, []AttestationAttribute, error) {
	// Parse response header
	responseHeader := [4]uint32{}
	if err := decode(data, &responseHeader, 4*4); err != nil {
		return nil, nil, err
	}
	attributeOffset := responseHeader[2] - (responseHeader[3] + 256)
	attestData := data[attributeOffset:]

	// Parse info header
	infoHeader := [4]uint16{}
	if err := decode(attestData, &infoHeader, 4*2); err != nil {
		return nil, nil, err
	}

	offset1 := infoHeader[2] // public key offset
	offset2 := infoHeader[3] // private key offset

	// Parse public key
	pubAttributes, err := parse(attestData[offset1:])
	if err != nil {
		return nil, nil, err
	}
	// Symmetric key attestation
	if offset2 == 0 {
		return pubAttributes, nil, nil
	}

	// Parse private key
	privAttributes, err := parse(attestData[offset2:])
	if err != nil {
		return nil, nil, err
	}

	return pubAttributes, privAttributes, nil
}

func parse(data []byte) ([]AttestationAttribute, error) {
	objectHeader := [3]uint32{}
	if err := decode(data, &objectHeader, 3*4); err != nil {
		return nil, err
	}

	count := int(objectHeader[1])
	attestData := data[12:]
	attributes := make([]AttestationAttribute, count)
	tlv := [2]uint32{}
	for i := range count {
		if err := decode(attestData, &tlv, 2*4); err != nil {
			return nil, err
		}
		attestData = attestData[8:]
		attributes[i] = AttestationAttribute{
			Type: tlv[0],
			Data: attestData[:tlv[1]],
		}
		attestData = attestData[tlv[1]:]
	}

	slices.SortFunc(attributes, func(a, b AttestationAttribute) int {
		switch {
		case a.Type < b.Type:
			return -1
		case a.Type > b.Type:
			return 1
		default:
			return 0
		}
	})
	return attributes, nil
}

// parseAttestationV1 parses attestation data using the Version 1 format. This
// code is based on the code of parse_v1.py from
// https://www.marvell.com/products/security-solutions/nitrox-hs-adapters/software-key-attestation.html
//
// Note that this format has not been tested, we don't have access to any
// attestation that uses this format.
func parseAttestationV1(data []byte, isSymmetricKey bool) ([]AttestationAttribute, []AttestationAttribute, error) {
	// Asymmetric key attestation objects start after 984 bytes.
	const CaviumAttestationAsymOffset = 984
	// Symmetric key attestation objects start after 24 bytes.
	const CaviumAttestationSymOffset = 24

	if isSymmetricKey {
		attributes, _, err := parseV1(data[CaviumAttestationAsymOffset:])
		if err != nil {
			return nil, nil, err
		}
		return attributes, nil, nil
	}

	pubAttributes, offset, err := parseV1(data[CaviumAttestationSymOffset:])
	if err != nil {
		return nil, nil, err
	}

	privAttributes, _, err := parseV1(data[CaviumAttestationSymOffset+offset:])
	if err != nil {
		return nil, nil, err
	}

	return pubAttributes, privAttributes, nil
}

func parseV1(data []byte) ([]AttestationAttribute, int, error) {
	header := [3]uint32{}
	if err := decode(data, &header, 3*4); err != nil {
		return nil, 0, err
	}
	count := int(header[1])
	objectHeaderSize := 12
	objectSize := int(header[2])
	attestData := data[objectHeaderSize:]

	attributes := make([]AttestationAttribute, count)
	tlv := [2]uint32{}
	for i := range count {
		if err := decode(attestData, &tlv, 2*4); err != nil {
			return nil, 0, err
		}
		attestData = attestData[8:]
		attributes[i] = AttestationAttribute{
			Type: tlv[0],
			Data: attestData[:tlv[1]],
		}
		attestData = attestData[tlv[1]:]
	}

	slices.SortFunc(attributes, func(a, b AttestationAttribute) int {
		switch {
		case a.Type < b.Type:
			return -1
		case a.Type > b.Type:
			return 1
		default:
			return 0
		}
	})
	return attributes, objectHeaderSize + objectSize, nil
}

func decode(data []byte, dest any, wantSize int) error {
	size, err := binary.Decode(data, binary.BigEndian, dest)
	if err != nil {
		return err
	}
	if size != wantSize {
		return io.EOF
	}
	return nil
}

func decodeUint32(data []byte, defValue uint32) uint32 {
	switch len(data) {
	case 1:
		return uint32(data[0])
	case 2:
		return uint32(binary.BigEndian.Uint16(data))
	case 4:
		return binary.BigEndian.Uint32(data)
	default:
		return defValue
	}
}

// getKeyType returns string version for a given CKK_* key type documented in
// the PCKS #11 standard. Not all of them are supported by CloudHSM,
func getKeyType(v uint32) string {
	switch v {
	case 0x0000:
		return "RSA"
	case 0x0001:
		return "DSA"
	case 0x0002:
		return "DH"
	case 0x0003:
		return "EC"
	case 0x0004:
		return "X9_42_DH"
	case 0x0005:
		return "KEA"
	case 0x0010:
		return "GENERIC_SECRET"
	case 0x0011:
		return "RC2"
	case 0x0012:
		return "RC4"
	case 0x0013:
		return "DES"
	case 0x0014:
		return "DES2"
	case 0x0015:
		return "DES3"
	case 0x0016:
		return "CAST"
	case 0x0017:
		return "CAST3"
	case 0x0018:
		return "CAST128"
	case 0x0019:
		return "RC5"
	case 0x001A:
		return "IDEA"
	case 0x001B:
		return "SKIPJACK"
	case 0x001C:
		return "BATON"
	case 0x001D:
		return "JUNIPER"
	case 0x001E:
		return "CDMF"
	case 0x001F:
		return "AES"
	case 0x0020:
		return "BLOWFISH"
	case 0x0021:
		return "TWOFISH"
	case 0x0022:
		return "SECURID"
	case 0x0023:
		return "HOTP"
	case 0x0024:
		return "ACTI"
	case 0x0025:
		return "CAMELLIA"
	case 0x0026:
		return "ARIA"
	case 0x0027:
		return "MD5_HMAC"
	case 0x0028:
		return "SHA_1_HMAC"
	case 0x0029:
		return "RIPEMD128_HMAC"
	case 0x002A:
		return "RIPEMD160_HMAC"
	case 0x002B:
		return "SHA256_HMAC"
	case 0x002C:
		return "SHA384_HMAC"
	case 0x002D:
		return "SHA512_HMAC"
	case 0x002E:
		return "SHA224_HMAC"
	case 0x002F:
		return "SEED"
	case 0x0030:
		return "GOSTR3410"
	case 0x0031:
		return "GOSTR3411"
	case 0x0032:
		return "GOST28147"
	case 0x80000000:
		return "VENDOR_DEFINED"
	default:
		return "UNKNOWN"
	}
}

func isSymmetric(alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) bool {
	switch alg {
	case kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION:
		return true
	case kmspb.CryptoKeyVersion_AES_128_GCM,
		kmspb.CryptoKeyVersion_AES_256_GCM,
		kmspb.CryptoKeyVersion_AES_128_CBC,
		kmspb.CryptoKeyVersion_AES_256_CBC,
		kmspb.CryptoKeyVersion_AES_128_CTR,
		kmspb.CryptoKeyVersion_AES_256_CTR:
		return true
	case kmspb.CryptoKeyVersion_HMAC_SHA256,
		kmspb.CryptoKeyVersion_HMAC_SHA1,
		kmspb.CryptoKeyVersion_HMAC_SHA384,
		kmspb.CryptoKeyVersion_HMAC_SHA512,
		kmspb.CryptoKeyVersion_HMAC_SHA224:
		return true
	case kmspb.CryptoKeyVersion_EXTERNAL_SYMMETRIC_ENCRYPTION:
		return true
	default:
		return false
	}
}
