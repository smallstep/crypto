package tss2

import (
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidLoadableKey   = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 3}
	oidImportableKey = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 4}
	oidSealedKey     = asn1.ObjectIdentifier{2, 23, 133, 10, 1, 5}
)

// TPMKey is defined in https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#section-3.1:
//
//	TPMKey ::= SEQUENCE {
//		type        OBJECT IDENTIFIER,
//		emptyAuth   [0] EXPLICIT BOOLEAN OPTIONAL,
//		policy      [1] EXPLICIT SEQUENCE OF TPMPolicy OPTIONAL,
//		secret      [2] EXPLICIT OCTET STRING OPTIONAL,
//		authPolicy  [3] EXPLICIT SEQUENCE OF TPMAuthPolicy OPTIONAL,
//		parent      INTEGER,
//		pubkey      OCTET STRING,
//		privkey     OCTET STRING
//	}
type TPMKey struct {
	Type       asn1.ObjectIdentifier
	EmptyAuth  bool            `asn1:"optional,explicit,tag:0"`
	Policy     []TPMPolicy     `asn1:"optional,explicit,tag:1"`
	Secret     []byte          `asn1:"optional,explicit,tag:2"`
	AuthPolicy []TPMAuthPolicy `asn1:"optional,explicit,tag:3"`
	Parent     int
	PublicKey  []byte
	PrivateKey []byte
}

// TPMPolicy is defined in https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#section-4.1:
//
//	TPMPolicy ::= SEQUENCE {
//		commandCode   [0] EXPLICIT INTEGER,
//		commandPolicy [1] EXPLICIT OCTET STRING
//	}
type TPMPolicy struct {
	CommandCode   int    `asn1:"explicit,tag:0"`
	CommandPolicy []byte `asn1:"explicit,tag:1"`
}

// TPMAuthPolicy is defined in https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#section-5.1
//
//	TPMAuthPolicy ::= SEQUENCE {
//		name    [0] EXPLICIT UTF8String OPTIONAL,
//		policy  [1] EXPLICIT SEQUENCE OF TPMPolicy
//	}
type TPMAuthPolicy struct {
	Name   string      `asn1:"utf8,optional,explicit,tag:0"`
	Policy []TPMPolicy `asn1:"explicit,tag:1"`
}

// ParsePrivateKey parses a single TPM key from the given ASN.1 DER data.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func ParsePrivateKey(derBytes []byte) (*TPMKey, error) {
	var err error

	input := cryptobyte.String(derBytes)
	if !input.ReadASN1(&input, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed TSS2 key")
	}

	key := new(TPMKey)
	if !input.ReadASN1ObjectIdentifier(&key.Type) {
		return nil, errors.New("malformed TSS2 type")
	}

	if tag, ok := readOptionalTag(&input, 0); ok {
		if !readASN1Boolean(&tag, &key.EmptyAuth) {
			return nil, errors.New("malformed TSS2 emptyAuth")
		}
	}

	// TODO(mariano): generate key with policy
	if tag, ok := readOptionalTag(&input, 1); ok {
		var policy cryptobyte.String
		if !tag.ReadASN1(&policy, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("malformed TSS2 policy")
		}
		key.Policy, err = readTPMPolicySequence(&policy)
		if err != nil {
			return nil, err
		}
	}

	// TODO(mariano): generate key with secret
	if tag, ok := readOptionalTag(&input, 2); ok {
		if key.Secret, ok = readOctetString(&tag); !ok {
			return nil, errors.New("malformed TSS2 secret")
		}
	}

	// TODO(mariano): generate key with authPolicy
	if tag, ok := readOptionalTag(&input, 3); ok {
		if key.AuthPolicy, err = readTPMAuthPolicy(&tag); err != nil {
			return nil, err
		}
	}

	if !input.ReadASN1Integer(&key.Parent) {
		return nil, errors.New("malformed TSS2 parent")
	}

	var ok bool
	if key.PublicKey, ok = readOctetString(&input); !ok {
		return nil, errors.New("malformed TSS2 pubkey")
	}

	if key.PrivateKey, ok = readOctetString(&input); !ok {
		return nil, errors.New("malformed TSS2 privkey")
	}

	return key, nil
}

// MarshalPrivateKey converts the give key to a TSS2 ASN.1 DER form.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func MarshalPrivateKey(key *TPMKey) ([]byte, error) {
	if key == nil {
		return nil, errors.New("tpmKey cannot be nil")
	}
	return asn1.Marshal(*key)
}

func readOptionalTag(input *cryptobyte.String, tag int) (cryptobyte.String, bool) {
	var isPresent bool
	var output cryptobyte.String
	if !input.ReadOptionalASN1(&output, &isPresent, cryptobyte_asn1.Tag(tag).Constructed().ContextSpecific()) {
		return nil, false
	}
	return output, isPresent
}

func readOctetString(input *cryptobyte.String) ([]byte, bool) {
	var os cryptobyte.String
	if !input.ReadASN1(&os, cryptobyte_asn1.OCTET_STRING) {
		return nil, false
	}
	return os, true
}

// readASN1Boolean accepts 0x01 as a TRUE value for a boolean type. OpenSSL
// seems to confuse DER with BER encoding and encodes the BOOLEAN TRUE as 0x01
// instead of 0xff.
func readASN1Boolean(input *cryptobyte.String, out *bool) bool {
	var bytes cryptobyte.String
	if !input.ReadASN1(&bytes, cryptobyte_asn1.BOOLEAN) || len(bytes) != 1 {
		return false
	}

	switch bytes[0] {
	case 0:
		*out = false
	case 1, 0xff:
		*out = true
	default:
		return false
	}

	return true
}

func readTPMPolicySequence(input *cryptobyte.String) ([]TPMPolicy, error) {
	var policies []TPMPolicy
	for !input.Empty() {
		var p TPMPolicy
		var seq cryptobyte.String
		if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("malformed TSS2 policy")
		}
		tag, ok := readOptionalTag(&seq, 0)
		if !ok || !tag.ReadASN1Integer(&p.CommandCode) {
			return nil, errors.New("malformed TSS2 policy commandCode")
		}
		tag, ok = readOptionalTag(&seq, 1)
		if !ok {
			return nil, errors.New("malformed TSS2 policy commandPolicy")
		}
		if p.CommandPolicy, ok = readOctetString(&tag); !ok {
			return nil, errors.New("malformed TSS2 policy commandPolicy")
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func readTPMAuthPolicy(input *cryptobyte.String) ([]TPMAuthPolicy, error) {
	var (
		err          error
		authPolicy   cryptobyte.String
		authPolicies []TPMAuthPolicy
	)
	if !input.ReadASN1(&authPolicy, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("malformed TSS2 authPolicy")
	}

	for !authPolicy.Empty() {
		var ap TPMAuthPolicy
		var seq cryptobyte.String
		if !authPolicy.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("malformed TSS2 authPolicy")
		}

		var name cryptobyte.String
		if tag, ok := readOptionalTag(&seq, 0); ok {
			if !tag.ReadASN1(&name, cryptobyte_asn1.UTF8String) {
				return nil, errors.New("malformed TSS2 authPolicy name")
			}
			ap.Name = string(name)
		}

		var policySeq cryptobyte.String
		if tag, ok := readOptionalTag(&seq, 1); ok {
			if !tag.ReadASN1(&policySeq, cryptobyte_asn1.SEQUENCE) {
				return nil, errors.New("malformed TSS2 authPolicy policy")
			}
			if ap.Policy, err = readTPMPolicySequence(&policySeq); err != nil {
				return nil, errors.New("malformed TSS2 authPolicy policy")
			}
		}
		authPolicies = append(authPolicies, ap)
	}

	return authPolicies, nil
}
