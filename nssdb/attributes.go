package nssdb

import "encoding/binary"

// CKA_CLASS values
// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/util/pkcs11t.h#L320-L334
const (
	CKO_DATA              = iota //nolint:staticcheck,revive // name matches source
	CKO_CERTIFICATE              //nolint:staticcheck,revive // name matches source
	CKO_PUBLIC_KEY               //nolint:staticcheck,revive // name matches source
	CKO_PRIVATE_KEY              //nolint:staticcheck,revive // name matches source
	CKO_SECRET_KEY               //nolint:staticcheck,revive // name matches source
	CKO_HW_FEATURE               //nolint:staticcheck,revive // name matches source
	CKO_DOMAIN_PARAMETERS        //nolint:staticcheck,revive // name matches source
	CKO_MECHANISM                //nolint:staticcheck,revive // name matches source
	CKO_PROFILE                  //nolint:staticcheck,revive // name matches source
)

// CKA_KEY_TYPE values
// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/util/pkcs11t.h#L366
const (
	CKK_RSA = iota //nolint:staticcheck,revive // name matches source
	CKK_DSA        //nolint:staticcheck,revive // name matches source
	CKK_DH         //nolint:staticcheck,revive // name matches source
	CKK_EC         //nolint:staticcheck,revive // name matches source
)

// CKA_CERTIFICATE_TYPE values
// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/util/pkcs11t.h#L453-L458
const (
	CKC_X_509           = iota //nolint:staticcheck,revive // name matches source
	CKC_X_509_ATTR_CERT        //nolint:staticcheck,revive // name matches source
	CKC_WTLS                   //nolint:staticcheck,revive // name matches source
)

// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkdb.c#L47
var ulongAttributes = map[string]bool{
	"CKA_CERTIFICATE_CATEGORY":      true,
	"CKA_CERTIFICATE_TYPE":          true,
	"CKA_CLASS":                     true,
	"CKA_JAVA_MIDP_SECURITY_DOMAIN": true,
	"CKA_KEY_GEN_MECHANISM":         true,
	"CKA_KEY_TYPE":                  true,
	"CKA_MECHANISM_TYPE":            true,
	"CKA_MODULUS_BITS":              true,
	"CKA_PRIME_BITS":                true,
	"CKA_SUBPRIME_BITS":             true,
	"CKA_VALUE_BITS":                true,
	"CKA_VALUE_LEN":                 true,
	"CKA_TRUST_DIGITAL_SIGNATURE":   true,
	"CKA_TRUST_NON_REPUDIATION":     true,
	"CKA_TRUST_KEY_ENCIPHERMENT":    true,
	"CKA_TRUST_DATA_ENCIPHERMENT":   true,
	"CKA_TRUST_KEY_AGREEMENT":       true,
	"CKA_TRUST_KEY_CERT_SIGN":       true,
	"CKA_TRUST_CRL_SIGN":            true,
	"CKA_TRUST_SERVER_AUTH":         true,
	"CKA_TRUST_CLIENT_AUTH":         true,
	"CKA_TRUST_CODE_SIGNING":        true,
	"CKA_TRUST_EMAIL_PROTECTION":    true,
	"CKA_TRUST_IPSEC_END_SYSTEM":    true,
	"CKA_TRUST_IPSEC_TUNNEL":        true,
	"CKA_TRUST_IPSEC_USER":          true,
	"CKA_TRUST_TIME_STAMPING":       true,
	"CKA_TRUST_STEP_UP_APPROVED":    true,
}

// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkdb.c#L89
var privateAttributes = map[string]bool{
	"CKA_VALUE":            true,
	"CKA_PRIVATE_EXPONENT": true,
	"CKA_PRIME_1":          true,
	"CKA_PRIME_2":          true,
	"CKA_EXPONENT_1":       true,
	"CKA_EXPONENT_2":       true,
	"CKA_COEFFICIENT":      true,
}

// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkdb.c#L108
//
//nolint:unused // unused
var authenticatedAttributes = map[string]bool{
	"CKA_MODULUS":                 true,
	"CKA_PUBLIC_EXPONENT":         true,
	"CKA_CERT_SHA1_HASH":          true,
	"CKA_CERT_MD5_HASH":           true,
	"CKA_TRUST_SERVER_AUTH":       true,
	"CKA_TRUST_CLIENT_AUTH":       true,
	"CKA_TRUST_EMAIL_PROTECTION":  true,
	"CKA_TRUST_CODE_SIGNING":      true,
	"CKA_TRUST_STEP_UP_APPROVED":  true,
	"CKA_NSS_OVERRIDE_EXTENSIONS": true,
}

// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkdb.c#L132
func encodeDBUlong(ul uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, ul)
	return buf
}

// https://github.com/nss-dev/nss/blob/NSS_3_107_RTM/lib/softoken/sftkdb.c#L146
func decodeDBUlong(buf []byte) uint32 {
	return binary.BigEndian.Uint32(buf)
}
