package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"go.step.sm/crypto/tlsutil"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func convertName(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "_", "")
}

// Names used for key usages.
var (
	KeyUsageDigitalSignature  = convertName("DigitalSignature")
	KeyUsageContentCommitment = convertName("ContentCommitment")
	KeyUsageKeyEncipherment   = convertName("KeyEncipherment")
	KeyUsageDataEncipherment  = convertName("DataEncipherment")
	KeyUsageKeyAgreement      = convertName("KeyAgreement")
	KeyUsageCertSign          = convertName("CertSign")
	KeyUsageCRLSign           = convertName("CRLSign")
	KeyUsageEncipherOnly      = convertName("EncipherOnly")
	KeyUsageDecipherOnly      = convertName("DecipherOnly")
)

// Names used for extended key usages.
var (
	ExtKeyUsageAny                            = convertName("Any")
	ExtKeyUsageServerAuth                     = convertName("ServerAuth")
	ExtKeyUsageClientAuth                     = convertName("ClientAuth")
	ExtKeyUsageCodeSigning                    = convertName("CodeSigning")
	ExtKeyUsageEmailProtection                = convertName("EmailProtection")
	ExtKeyUsageIPSECEndSystem                 = convertName("IPSECEndSystem")
	ExtKeyUsageIPSECTunnel                    = convertName("IPSECTunnel")
	ExtKeyUsageIPSECUser                      = convertName("IPSECUser")
	ExtKeyUsageTimeStamping                   = convertName("TimeStamping")
	ExtKeyUsageOCSPSigning                    = convertName("OCSPSigning")
	ExtKeyUsageMicrosoftServerGatedCrypto     = convertName("MicrosoftServerGatedCrypto")
	ExtKeyUsageNetscapeServerGatedCrypto      = convertName("NetscapeServerGatedCrypto")
	ExtKeyUsageMicrosoftCommercialCodeSigning = convertName("MicrosoftCommercialCodeSigning")
	ExtKeyUsageMicrosoftKernelCodeSigning     = convertName("MicrosoftKernelCodeSigning")
)

// Names used and SubjectAlternativeNames types.
const (
	AutoType          = "auto"
	EmailType         = "email" // also known as 'rfc822Name' in RFC 5280
	DNSType           = "dns"
	X400AddressType   = "x400Address"
	DirectoryNameType = "dn"
	EDIPartyNameType  = "ediPartyName"
	URIType           = "uri"
	IPType            = "ip"
	RegisteredIDType  = "registeredID"
)

// These type ids are defined in RFC 5280 page 36
const (
	nameTypeOtherName = 0
	nameTypeEmail     = 1
	nameTypeDNS       = 2
	//nameTypeX400         = 3
	//nameTypeDirectory    = 4
	//nameTypeEDI          = 5
	nameTypeURI          = 6
	nameTypeIP           = 7
	nameTypeRegisteredID = 8
)

const sanTypeSeparator = ";"

// OtherNameValue is a simple struct to ensure the ASN1 marshaller
// creates an EXPLICIT asn1 type when creating the OtherName
type OtherNameValue struct {
	V interface{}
}

// OtherName holds a SubjectAlternativeName type OtherName as defined in RFC 5280
type OtherName struct {
	OID   asn1.ObjectIdentifier
	Value OtherNameValue `asn1:"tag:0"`
}

// Extension is the JSON representation of a raw X.509 extensions.
type Extension struct {
	ID       ObjectIdentifier `json:"id"`
	Critical bool             `json:"critical"`
	Value    []byte           `json:"value"`
}

// newExtension creates an Extension from a standard pkix.Extension.
func newExtension(e pkix.Extension) Extension {
	return Extension{
		ID:       ObjectIdentifier(e.Id),
		Critical: e.Critical,
		Value:    e.Value,
	}
}

// newExtensions creates a slice of Extension from a slice of pkix.Exntesion.
func newExtensions(extensions []pkix.Extension) []Extension {
	if extensions == nil {
		return nil
	}
	ret := make([]Extension, len(extensions))
	for i, e := range extensions {
		ret[i] = newExtension(e)
	}
	return ret

}

// Set adds the extension to the given X509 certificate.
func (e Extension) Set(c *x509.Certificate) {
	c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier(e.ID),
		Critical: e.Critical,
		Value:    e.Value,
	})
}

// ObjectIdentifier represents a JSON strings that unmarshals into an ASN1
// object identifier or OID.
type ObjectIdentifier asn1.ObjectIdentifier

// MarshalJSON implements the json.Marshaler interface and returns the string
// version of the asn1.ObjectIdentifier.
func (o ObjectIdentifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(asn1.ObjectIdentifier(o).String())
}

// UnmarshalJSON implements the json.Unmarshaler interface and coverts a strings
// like "2.5.29.17" into an ASN1 object identifier.
func (o *ObjectIdentifier) UnmarshalJSON(data []byte) error {
	s, err := unmarshalString(data)
	if err != nil {
		return err
	}

	oid, err := parseObjectIdentifier(s)
	if err != nil {
		return err
	}
	*o = ObjectIdentifier(oid)
	return nil
}

// SubjectAlternativeName represents a X.509 subject alternative name. Types
// supported are "dns", "email", "ip", "uri". A special type "auto" or "" can be
// used to try to guess the type of the value.
type SubjectAlternativeName struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Set sets the subject alternative name in the given x509.Certificate.
func (s SubjectAlternativeName) Set(c *x509.Certificate) {
	switch strings.ToLower(s.Type) {
	case DNSType:
		c.DNSNames = append(c.DNSNames, s.Value)
	case EmailType:
		c.EmailAddresses = append(c.EmailAddresses, s.Value)
	case IPType:
		// The validation of the IP would happen in the unmarshaling, but just
		// to be sure we are only adding valid IPs.
		if ip := net.ParseIP(s.Value); ip != nil {
			c.IPAddresses = append(c.IPAddresses, ip)
		}
	case URIType:
		if u, err := url.Parse(s.Value); err == nil {
			c.URIs = append(c.URIs, u)
		}
	case "", AutoType:
		dnsNames, ips, emails, uris := SplitSANs([]string{s.Value})
		c.DNSNames = append(c.DNSNames, dnsNames...)
		c.IPAddresses = append(c.IPAddresses, ips...)
		c.EmailAddresses = append(c.EmailAddresses, emails...)
		c.URIs = append(c.URIs, uris...)
	default:
		panic(fmt.Sprintf("unsupported subject alternative name type %s", s.Type))
	}
}

func (s SubjectAlternativeName) RawValue() (*asn1.RawValue, error) {
	var asnValue asn1.RawValue

	switch s.Type {
	case "", AutoType:
		// autotype requires us to find out what the type is
		if ip := net.ParseIP(s.Value); ip != nil {
			return SubjectAlternativeName{Type: IPType, Value: s.Value}.RawValue()
		} else if u, err := url.Parse(s.Value); err == nil && u.Scheme != "" {
			return SubjectAlternativeName{Type: URIType, Value: s.Value}.RawValue()
		} else if strings.Contains(s.Value, "@") {
			return SubjectAlternativeName{Type: EmailType, Value: s.Value}.RawValue()
		} else {
			return SubjectAlternativeName{Type: DNSType, Value: s.Value}.RawValue()
		}
	case EmailType:
		valid := isIA5String(s.Value)
		if !valid {
			return nil, fmt.Errorf("error converting SAN type %s value to ia5", s.Type)
		}
		asnValue = asn1.RawValue{Tag: nameTypeEmail, Class: asn1.ClassContextSpecific, Bytes: []byte(s.Value)}
	case DNSType:
		ia5String, err := tlsutil.SanitizeName(s.Value) // use SanitizeName for DNS types because it will do some character replacement and verify that its an acceptable hostname
		if err != nil {
			return nil, errors.Wrapf(err, "error converting SAN type %s value to ia5", s.Type)
		}
		asnValue = asn1.RawValue{Tag: nameTypeDNS, Class: asn1.ClassContextSpecific, Bytes: []byte(ia5String)}
	case X400AddressType, DirectoryNameType, EDIPartyNameType:
		return nil, fmt.Errorf("unimplemented SAN type %s", s.Type)
	case URIType:
		valid := isIA5String(s.Value)
		if !valid {
			return nil, fmt.Errorf("error converting SAN type %s value to ia5", s.Type)
		}
		asnValue = asn1.RawValue{Tag: nameTypeURI, Class: asn1.ClassContextSpecific, Bytes: []byte(s.Value)}
	case IPType:
		if rawIP := net.ParseIP(s.Value); rawIP != nil {
			ip := rawIP.To4()
			if ip == nil {
				ip = rawIP
			}
			asnValue = asn1.RawValue{Tag: nameTypeIP, Class: asn1.ClassContextSpecific, Bytes: ip}
		} else {
			return nil, fmt.Errorf("cannot convert %s to IP", s.Value)
		}
	case RegisteredIDType:
		if s.Value != "" {
			oid, err := parseObjectIdentifier(s.Value)
			if err == nil {
				rawBytes, err := asn1.MarshalWithParams(oid, fmt.Sprintf("tag:%d", nameTypeRegisteredID))
				if err != nil {
					return nil, errors.Wrap(err, "unable to Marshal RegisteredID SAN")
				}
				asnValue = asn1.RawValue{FullBytes: rawBytes}
			} else {
				return nil, errors.Wrap(err, "error parsing OID for RegisteredID SAN")
			}
		} else {
			return nil, errors.New("blank RegisteredID SAN is not allowed")
		}
	default:
		// if san.Type is a valid OID, we assume it is an OtherName
		oid, err := parseObjectIdentifier(s.Type)
		if err == nil {
			// the OtherName value can be any type depending on the OID
			// ASN supports a great number of formats (https://www.openssl.org/docs/man1.0.2/man3/ASN1_generate_nconf.html),
			// but golang's asn1 lib supports much fewer -- for now support anything the golang asn1 marshaller supports

			// The default type is printable, but if the value is prefixed with a type, use that
			var valueType = "printable"
			var sanValue = s.Value
			var rawBytes []byte
			var err error

			if strings.Contains(s.Value, sanTypeSeparator) {
				valueType = strings.Split(s.Value, sanTypeSeparator)[0]
				sanValue = s.Value[len(valueType)+1:]
			}

			switch valueType {
			case "int":
				var i int
				i, err = strconv.Atoi(sanValue)
				if err != nil {
					return nil, errors.Wrapf(err, "invalid int value for int-typed SAN OtherName %s", s.Type)
				}
				rawBytes, err = asn1.Marshal(i)
			case "oid":
				var oidVal asn1.ObjectIdentifier
				oidVal, err = parseObjectIdentifier(sanValue)
				if err != nil {
					return nil, errors.Wrapf(err, "invalid OID value for OID-typed SAN OtherName %s", s.Type)
				}

				rawBytes, err = asn1.Marshal(oidVal)
			case "raw":
				// the raw type accepts a base64 encoded byte array which is passed unaltered into the ASN
				// marshaller. By using this type users can add ASN1 data types manually into templates
				// to support some unsupported types like BMPString, Octet String, and others
				rawBytes, err = base64.StdEncoding.DecodeString(sanValue)
			case "utf8":
				if !isUTF8String(sanValue) {
					return nil, fmt.Errorf("SAN type %s value %s is not UTF8", s.Type, sanValue)
				}
				rawBytes, err = asn1.MarshalWithParams(sanValue, valueType)
			case "ia5":
				if !isIA5String(sanValue) {
					return nil, fmt.Errorf("SAN type %s value %s is not IA5", s.Type, sanValue)
				}
				rawBytes, err = asn1.MarshalWithParams(sanValue, valueType)
			case "numeric":
				if !isNumericString(sanValue) {
					return nil, fmt.Errorf("SAN type %s value %s is not numeric", s.Type, sanValue)
				}
				rawBytes, err = asn1.MarshalWithParams(sanValue, valueType)
			case "printable":
				if !isPrintableString(sanValue, true, true) {
					return nil, fmt.Errorf("SAN type %s value %s is not printable", s.Type, sanValue)
				}
				rawBytes, err = asn1.MarshalWithParams(sanValue, valueType)
			default:
				// if it's an unknown type, default to printable - but use the entire value specified in case there is a semicolon in the value
				if !isPrintableString(sanValue, true, true) {
					return nil, fmt.Errorf("SAN type %s value %s is not printable", s.Type, sanValue)
				}
				rawBytes, err = asn1.MarshalWithParams(sanValue, "printable")
			}

			if err != nil {
				return nil, errors.Wrapf(err, "could not marshal ASN1 value %v", s.Value)
			}

			// OtherName SANs are an ASN1 sequence containing OID and Value
			otherName := OtherName{
				OID: oid,
				Value: OtherNameValue{
					V: asn1.RawValue{FullBytes: rawBytes}, //load in the raw OtherName value
				},
			}
			otherNameBytes, err := asn1.MarshalWithParams(otherName, fmt.Sprintf("tag:%d", nameTypeOtherName)) //use MarshalWithParams so we can set the context-specific tag - in this case 0
			if err != nil {
				return nil, errors.Wrap(err, "unable to Marshal otherName SAN")
			}
			asnValue = asn1.RawValue{FullBytes: otherNameBytes}
		} else {
			return nil, fmt.Errorf("unsupported SAN type %s", s.Type)
		}
	}

	return &asnValue, nil
}

// KeyUsage type represents the JSON array used to represent the key usages of a
// X509 certificate.
type KeyUsage x509.KeyUsage

// Set sets the key usage to the given certificate.
func (k KeyUsage) Set(c *x509.Certificate) {
	c.KeyUsage = x509.KeyUsage(k)
}

// UnmarshalJSON implements the json.Unmarshaler interface and coverts a string
// or a list of strings into a key usage.
func (k *KeyUsage) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}

	*k = 0

	for _, s := range ms {
		var ku x509.KeyUsage
		switch convertName(s) {
		case KeyUsageDigitalSignature:
			ku = x509.KeyUsageDigitalSignature
		case KeyUsageContentCommitment:
			ku = x509.KeyUsageContentCommitment
		case KeyUsageKeyEncipherment:
			ku = x509.KeyUsageKeyEncipherment
		case KeyUsageDataEncipherment:
			ku = x509.KeyUsageDataEncipherment
		case KeyUsageKeyAgreement:
			ku = x509.KeyUsageKeyAgreement
		case KeyUsageCertSign:
			ku = x509.KeyUsageCertSign
		case KeyUsageCRLSign:
			ku = x509.KeyUsageCRLSign
		case KeyUsageEncipherOnly:
			ku = x509.KeyUsageEncipherOnly
		case KeyUsageDecipherOnly:
			ku = x509.KeyUsageDecipherOnly
		default:
			return errors.Errorf("unsupported keyUsage %s", s)
		}
		*k |= KeyUsage(ku)
	}

	return nil
}

// ExtKeyUsage represents a JSON array of extended key usages.
type ExtKeyUsage []x509.ExtKeyUsage

// Set sets the extended key usages in the given certificate.
func (k ExtKeyUsage) Set(c *x509.Certificate) {
	c.ExtKeyUsage = []x509.ExtKeyUsage(k)
}

// UnmarshalJSON implements the json.Unmarshaler interface and coverts a string
// or a list of strings into a list of extended key usages.
func (k *ExtKeyUsage) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}

	eku := make([]x509.ExtKeyUsage, len(ms))
	for i, s := range ms {
		var ku x509.ExtKeyUsage
		switch convertName(s) {
		case ExtKeyUsageAny:
			ku = x509.ExtKeyUsageAny
		case ExtKeyUsageServerAuth:
			ku = x509.ExtKeyUsageServerAuth
		case ExtKeyUsageClientAuth:
			ku = x509.ExtKeyUsageClientAuth
		case ExtKeyUsageCodeSigning:
			ku = x509.ExtKeyUsageCodeSigning
		case ExtKeyUsageEmailProtection:
			ku = x509.ExtKeyUsageEmailProtection
		case ExtKeyUsageIPSECEndSystem:
			ku = x509.ExtKeyUsageIPSECEndSystem
		case ExtKeyUsageIPSECTunnel:
			ku = x509.ExtKeyUsageIPSECTunnel
		case ExtKeyUsageIPSECUser:
			ku = x509.ExtKeyUsageIPSECUser
		case ExtKeyUsageTimeStamping:
			ku = x509.ExtKeyUsageTimeStamping
		case ExtKeyUsageOCSPSigning:
			ku = x509.ExtKeyUsageOCSPSigning
		case ExtKeyUsageMicrosoftServerGatedCrypto:
			ku = x509.ExtKeyUsageMicrosoftServerGatedCrypto
		case ExtKeyUsageNetscapeServerGatedCrypto:
			ku = x509.ExtKeyUsageNetscapeServerGatedCrypto
		case ExtKeyUsageMicrosoftCommercialCodeSigning:
			ku = x509.ExtKeyUsageMicrosoftCommercialCodeSigning
		case ExtKeyUsageMicrosoftKernelCodeSigning:
			ku = x509.ExtKeyUsageMicrosoftKernelCodeSigning
		default:
			return errors.Errorf("unsupported extKeyUsage %s", s)
		}
		eku[i] = ku
	}

	*k = ExtKeyUsage(eku)
	return nil
}

// UnknownExtKeyUsage represents the list of OIDs of extended key usages unknown
// to crypto/x509.
type UnknownExtKeyUsage MultiObjectIdentifier

// MarshalJSON implements the json.Marshaler interface in UnknownExtKeyUsage.
func (u UnknownExtKeyUsage) MarshalJSON() ([]byte, error) {
	return MultiObjectIdentifier(u).MarshalJSON()
}

// UnmarshalJSON implements the json.Unmarshaler interface in UnknownExtKeyUsage.
func (u *UnknownExtKeyUsage) UnmarshalJSON(data []byte) error {
	var v MultiObjectIdentifier
	if err := json.Unmarshal(data, &v); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	*u = UnknownExtKeyUsage(v)
	return nil
}

// Set sets the policy identifiers to the given certificate.
func (u UnknownExtKeyUsage) Set(c *x509.Certificate) {
	c.UnknownExtKeyUsage = u
}

// SubjectKeyID represents the binary value of the subject key identifier
// extension, this should be the SHA-1 hash of the public key. In JSON this
// value should be a base64-encoded string, and in most cases it should not be
// set because it will be automatically generated.
type SubjectKeyID []byte

// Set sets the subject key identifier to the given certificate.
func (id SubjectKeyID) Set(c *x509.Certificate) {
	c.SubjectKeyId = id
}

// AuthorityKeyID represents the binary value of the authority key identifier
// extension. It should be the subject key identifier of the parent certificate.
// In JSON this value should be a base64-encoded string, and in most cases it
// should not be set, as it will be automatically provided.
type AuthorityKeyID []byte

// Set sets the authority key identifier to the given certificate.
func (id AuthorityKeyID) Set(c *x509.Certificate) {
	c.AuthorityKeyId = id
}

// OCSPServer contains the list of OSCP servers that will be encoded in the
// authority information access extension.
type OCSPServer MultiString

// UnmarshalJSON implements the json.Unmarshaler interface in OCSPServer.
func (o *OCSPServer) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	*o = ms
	return nil
}

// Set sets the list of OSCP servers to the given certificate.
func (o OCSPServer) Set(c *x509.Certificate) {
	c.OCSPServer = o
}

// IssuingCertificateURL contains the list of the issuing certificate url that
// will be encoded in the authority information access extension.
type IssuingCertificateURL MultiString

// UnmarshalJSON implements the json.Unmarshaler interface in IssuingCertificateURL.
func (u *IssuingCertificateURL) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	*u = ms
	return nil
}

// Set sets the list of issuing certificate urls to the given certificate.
func (u IssuingCertificateURL) Set(c *x509.Certificate) {
	c.IssuingCertificateURL = u
}

// CRLDistributionPoints contains the list of CRL distribution points that will
// be encoded in the CRL distribution points extension.
type CRLDistributionPoints MultiString

// UnmarshalJSON implements the json.Unmarshaler interface in CRLDistributionPoints.
func (u *CRLDistributionPoints) UnmarshalJSON(data []byte) error {
	ms, err := unmarshalMultiString(data)
	if err != nil {
		return err
	}
	*u = ms
	return nil
}

// Set sets the CRL distribution points to the given certificate.
func (u CRLDistributionPoints) Set(c *x509.Certificate) {
	c.CRLDistributionPoints = u
}

// PolicyIdentifiers represents the list of OIDs to set in the certificate
// policies extension.
type PolicyIdentifiers MultiObjectIdentifier

// MarshalJSON implements the json.Marshaler interface in PolicyIdentifiers.
func (p PolicyIdentifiers) MarshalJSON() ([]byte, error) {
	return MultiObjectIdentifier(p).MarshalJSON()
}

// UnmarshalJSON implements the json.Unmarshaler interface in PolicyIdentifiers.
func (p *PolicyIdentifiers) UnmarshalJSON(data []byte) error {
	var v MultiObjectIdentifier
	if err := json.Unmarshal(data, &v); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	*p = PolicyIdentifiers(v)
	return nil
}

// Set sets the policy identifiers to the given certificate.
func (p PolicyIdentifiers) Set(c *x509.Certificate) {
	c.PolicyIdentifiers = p
}

// BasicConstraints represents the X509 basic constraints extension and defines
// if a certificate is a CA and then maximum depth of valid certification paths
// that include the certificate. A MaxPathLen of zero indicates that no non-
// self-issued intermediate CA certificates may follow in a valid certification
// path. To do not impose a limit the MaxPathLen should be set to -1.
type BasicConstraints struct {
	IsCA       bool `json:"isCA"`
	MaxPathLen int  `json:"maxPathLen"`
}

// Set sets the basic constraints to the given certificate.
func (b BasicConstraints) Set(c *x509.Certificate) {
	c.BasicConstraintsValid = true
	c.IsCA = b.IsCA
	if c.IsCA {
		switch {
		case b.MaxPathLen == 0:
			c.MaxPathLen = 0
			c.MaxPathLenZero = true
		case b.MaxPathLen < 0:
			c.MaxPathLen = -1
			c.MaxPathLenZero = false
		default:
			c.MaxPathLen = b.MaxPathLen
			c.MaxPathLenZero = false
		}
	} else {
		c.MaxPathLen = 0
		c.MaxPathLenZero = false
	}
}

// NameConstraints represents the X509 Name constraints extension and defines a
// names space within which all subject names in subsequent certificates in a
// certificate path must be located. The name constraints extension must be used
// only in a CA.
type NameConstraints struct {
	Critical                bool        `json:"critical"`
	PermittedDNSDomains     MultiString `json:"permittedDNSDomains"`
	ExcludedDNSDomains      MultiString `json:"excludedDNSDomains"`
	PermittedIPRanges       MultiIPNet  `json:"permittedIPRanges"`
	ExcludedIPRanges        MultiIPNet  `json:"excludedIPRanges"`
	PermittedEmailAddresses MultiString `json:"permittedEmailAddresses"`
	ExcludedEmailAddresses  MultiString `json:"excludedEmailAddresses"`
	PermittedURIDomains     MultiString `json:"permittedURIDomains"`
	ExcludedURIDomains      MultiString `json:"excludedURIDomains"`
}

// Set sets the name constraints in the given certificate.
func (n NameConstraints) Set(c *x509.Certificate) {
	c.PermittedDNSDomainsCritical = n.Critical
	c.PermittedDNSDomains = n.PermittedDNSDomains
	c.ExcludedDNSDomains = n.ExcludedDNSDomains
	c.PermittedIPRanges = n.PermittedIPRanges
	c.ExcludedIPRanges = n.ExcludedIPRanges
	c.PermittedEmailAddresses = n.PermittedEmailAddresses
	c.ExcludedEmailAddresses = n.ExcludedEmailAddresses
	c.PermittedURIDomains = n.PermittedURIDomains
	c.ExcludedURIDomains = n.ExcludedURIDomains
}

// SerialNumber is the JSON representation of the X509 serial number.
type SerialNumber struct {
	*big.Int
}

// Set sets the serial number in the given certificate.
func (s SerialNumber) Set(c *x509.Certificate) {
	c.SerialNumber = s.Int
}

// MarshalJSON implements the json.Marshaler interface, and encodes a
// SerialNumber using the big.Int marshaler.
func (s *SerialNumber) MarshalJSON() ([]byte, error) {
	if s == nil || s.Int == nil {
		return []byte(`null`), nil
	}
	return s.Int.MarshalJSON()
}

// UnmarshalJSON implements the json.Unmarshal interface and unmarshals an
// integer or a string into a serial number. If a string is used, a prefix of
// “0b” or “0B” selects base 2, “0”, “0o” or “0O” selects base 8, and “0x” or
// “0X” selects base 16. Otherwise, the selected base is 10 and no prefix is
// accepted.
func (s *SerialNumber) UnmarshalJSON(data []byte) error {
	if sn, ok := maybeString(data); ok {
		// Using base 0 to accept prefixes 0b, 0o, 0x but defaults as base 10.
		b, ok := new(big.Int).SetString(sn, 0)
		if !ok {
			return errors.Errorf("error unmarshaling json: serialNumber %s is not valid", sn)
		}
		*s = SerialNumber{
			Int: b,
		}
		return nil
	}

	// Assume a number.
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return errors.Wrap(err, "error unmarshaling json")
	}
	*s = SerialNumber{
		Int: new(big.Int).SetInt64(i),
	}
	return nil
}

// createSubjectAltNameExtension will construct an Extension containing all
// SubjectAlternativeNames held in a Certificate. It implements more types than
// the golang x509 library, so it is used whenever OtherName or RegisteredID
// type SANs are present in the certificate.
// See also https://datatracker.ietf.org/doc/html/rfc5280.html#section-4.2.1.6
// TODO: X400Address, DirectoryName, and EDIPartyName types are defined in RFC5280
//       but are currently unimplemented
func createSubjectAltNameExtension(c *Certificate, subjectIsEmpty bool) (*Extension, error) {
	// golang x509 lib does not support all SAN types, to support other types (e.g. otherName, registeredID, etc.)
	// we need to generate the extension manually

	var rawValues []interface{}

	for _, dnsName := range c.DNSNames {
		rawValue, err := SubjectAlternativeName{
			Type:  DNSType,
			Value: dnsName,
		}.RawValue()

		if err != nil {
			return nil, err
		}

		rawValues = append(rawValues, *rawValue)
	}

	for _, emailAddress := range c.DNSNames {
		rawValue, err := SubjectAlternativeName{
			Type:  EmailType,
			Value: emailAddress,
		}.RawValue()

		if err != nil {
			return nil, err
		}

		rawValues = append(rawValues, *rawValue)
	}

	for _, uri := range c.URIs {
		rawValue, err := SubjectAlternativeName{
			Type:  URIType,
			Value: uri.String(),
		}.RawValue()

		if err != nil {
			return nil, err
		}

		rawValues = append(rawValues, *rawValue)
	}

	for _, ip := range c.IPAddresses {
		rawValue, err := SubjectAlternativeName{
			Type:  IPType,
			Value: ip.String(),
		}.RawValue()

		if err != nil {
			return nil, err
		}

		rawValues = append(rawValues, *rawValue)
	}

	for _, san := range c.SANs {
		rawValue, err := san.RawValue()

		if err != nil {
			return nil, err
		}

		rawValues = append(rawValues, *rawValue)
	}

	// Now marshal the rawValues into the ASN1 sequence, and create an Extension object to hold the extension
	rawBytes, err := asn1.Marshal(rawValues)
	if err != nil {
		return nil, errors.Wrap(err, "error marshalling SubjectAlternativeName extension to ASN1")
	}

	subjectAltNameExtension := Extension{
		ID:       oidExtensionSubjectAltName,
		Critical: subjectIsEmpty,
		Value:    rawBytes,
	}

	return &subjectAltNameExtension, nil
}
