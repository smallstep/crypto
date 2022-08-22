package x509util

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha1" // nolint:gosec // SubjectKeyIdentifier by RFC 5280
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"net"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/pkg/errors"
	"golang.org/x/net/idna"
)

// FingerprintEncoding defines the supported encodigns in certificate
// fingerprints.
type FingerprintEncoding int

// Supported fingerprint encodings.
const (
	HexFingerprint FingerprintEncoding = iota
	Base64Fingerprint
	Base64UrlFingerprint
)

var emptyASN1Subject = []byte{0x30, 0}

// SanitizeName converts the given domain to its ASCII form.
func SanitizeName(domain string) (string, error) {
	if domain == "" {
		return "", errors.New("empty server name")
	}

	// Note that this conversion is necessary because some server names in the handshakes
	// started by some clients (such as cURL) are not converted to Punycode, which will
	// prevent us from obtaining certificates for them. In addition, we should also treat
	// example.com and EXAMPLE.COM as equivalent and return the same certificate for them.
	// Fortunately, this conversion also helped us deal with this kind of mixedcase problems.
	//
	// Due to the "σςΣ" problem (see https://unicode.org/faq/idn.html#22), we can't use
	// idna.Punycode.ToASCII (or just idna.ToASCII) here.
	name, err := idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", errors.New("server name contains invalid character")
	}

	return name, nil
}

// SplitSANs splits a slice of Subject Alternative Names into slices of
// IP Addresses and DNS Names. If an element is not an IP address, then it
// is bucketed as a DNS Name.
func SplitSANs(sans []string) (dnsNames []string, ips []net.IP, emails []string, uris []*url.URL) {
	dnsNames = []string{}
	ips = []net.IP{}
	emails = []string{}
	uris = []*url.URL{}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			ips = append(ips, ip)
		} else if u, err := url.Parse(san); err == nil && u.Scheme != "" {
			uris = append(uris, u)
		} else if strings.Contains(san, "@") {
			emails = append(emails, san)
		} else {
			dnsNames = append(dnsNames, san)
		}
	}
	return
}

// CreateSANs splits the given sans and returns a list of SubjectAlternativeName
// structs.
func CreateSANs(sans []string) []SubjectAlternativeName {
	dnsNames, ips, emails, uris := SplitSANs(sans)
	sanTypes := make([]SubjectAlternativeName, 0, len(sans))
	for _, v := range dnsNames {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "dns", Value: v})
	}
	for _, v := range ips {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "ip", Value: v.String()})
	}
	for _, v := range emails {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "email", Value: v})
	}
	for _, v := range uris {
		sanTypes = append(sanTypes, SubjectAlternativeName{Type: "uri", Value: v.String()})
	}
	return sanTypes
}

// Fingerprint returns the SHA-256 fingerprint of the certificate.
func Fingerprint(cert *x509.Certificate) string {
	return EncodedFingerprint(cert, HexFingerprint)
}

// EncodedFingerprint returns an encoded the SHA-256 fingerprint of the
// certificate using the specified encoding. In an invalid encoding is passed,
// the return value will be an empty string.
func EncodedFingerprint(cert *x509.Certificate, encoding FingerprintEncoding) string {
	sum := sha256.Sum256(cert.Raw)
	switch encoding {
	case HexFingerprint:
		return strings.ToLower(hex.EncodeToString(sum[:]))
	case Base64Fingerprint:
		return base64.StdEncoding.EncodeToString(sum[:])
	case Base64UrlFingerprint:
		return base64.URLEncoding.EncodeToString(sum[:])
	default:
		return ""
	}
}

// generateSerialNumber returns a random serial number.
func generateSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, errors.Wrap(err, "error generating serial number")
	}
	return sn, nil
}

// subjectPublicKeyInfo is a PKIX public key structure defined in RFC 5280.
type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// generateSubjectKeyID generates the key identifier according the the RFC 5280
// section 4.2.1.2.
//
// The keyIdentifier is composed of the 160-bit SHA-1 hash of the value of the
// BIT STRING subjectPublicKey (excluding the tag, length, and number of unused
// bits).
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, errors.Wrap(err, "error marshaling public key")
	}
	var info subjectPublicKeyInfo
	if _, err = asn1.Unmarshal(b, &info); err != nil {
		return nil, errors.Wrap(err, "error unmarshaling public key")
	}
	// nolint:gosec // SubjectKeyIdentifier by RFC 5280
	hash := sha1.Sum(info.SubjectPublicKey.Bytes)
	return hash[:], nil
}

// subjectIsEmpty returns whether the given pkix.Name (aka Subject) is an empty sequence
func subjectIsEmpty(s pkix.Name) bool {
	if asn1Subject, err := asn1.Marshal(s.ToRDNSequence()); err == nil {
		return bytes.Equal(asn1Subject, emptyASN1Subject)
	}

	return false
}

// isUTF8String reports whether the given s is a valid utf8 string
func isUTF8String(s string) bool {
	return utf8.ValidString(s)
}

// isIA5String reports whether the given s is a valid ia5 string.
func isIA5String(s string) bool {
	for _, r := range s {
		// Per RFC5280 "IA5String is limited to the set of ASCII characters"
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// isNumeric reports whether the given s is a valid ASN1 NumericString.
func isNumericString(s string) bool {
	for _, b := range s {
		valid := '0' <= b && b <= '9' || b == ' '
		if !valid {
			return false
		}
	}

	return true
}

// isPrintableString reports whether the given s is a valid ASN.1 PrintableString.
// If asterisk is allowAsterisk then '*' is also allowed, reflecting existing
// practice. If ampersand is allowAmpersand then '&' is allowed as well.
func isPrintableString(s string, asterisk, ampersand bool) bool {
	for _, b := range s {
		valid := 'a' <= b && b <= 'z' ||
			'A' <= b && b <= 'Z' ||
			'0' <= b && b <= '9' ||
			'\'' <= b && b <= ')' ||
			'+' <= b && b <= '/' ||
			b == ' ' ||
			b == ':' ||
			b == '=' ||
			b == '?' ||
			// This is technically not allowed in a PrintableString.
			// However, x509 certificates with wildcard strings don't
			// always use the correct string type so we permit it.
			(bool(asterisk) && b == '*') ||
			// This is not technically allowed either. However, not
			// only is it relatively common, but there are also a
			// handful of CA certificates that contain it. At least
			// one of which will not expire until 2027.
			(bool(ampersand) && b == '&')

		if !valid {
			return false
		}
	}

	return true
}
