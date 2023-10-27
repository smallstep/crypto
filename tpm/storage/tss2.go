package storage

import (
	"encoding/asn1"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
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
	Policy     []TPMPolicy     `asn1:"optional,explicit,tag:0"`
	Secret     []byte          `asn1:"optional,explicit,tag:0"`
	AuthPolicy []TPMAuthPolicy `asn1:"optional,explicit,tag:0"`
	Parent     int
	Pubkey     []byte
	Privkey    []byte
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

func ParseTSS2PrivateKey(derBytes []byte) (*TPMKey, error) {
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

	var err error
	var isPresent bool

	// TODO(mariano): generate key with policy
	if tag, ok := readOptionalTag(&input, 1); ok {
		var policy cryptobyte.String
		if !tag.ReadOptionalASN1(&policy, &isPresent, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("malformed TSS2 policy")
		}
		if isPresent {
			key.Policy, err = readTPMPolicySequence(&policy)
			if err != nil {
				return nil, err
			}
		}
	}

	// TODO(mariano): generate key with secret
	if tag, ok := readOptionalTag(&input, 2); ok {
		if !tag.ReadOptionalASN1OctetString(&key.Secret, &isPresent, cryptobyte_asn1.OCTET_STRING) {
			return nil, errors.New("malformed TSS2 secret")
		}
	}

	// TODO(mariano): generate key with authPolicy
	if tag, ok := readOptionalTag(&input, 3); ok {
		var authPolicy cryptobyte.String
		if !tag.ReadOptionalASN1(&authPolicy, &isPresent, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("malformed TSS2 authPolicy")
		}
		if isPresent {
			var policy cryptobyte.String
			for !authPolicy.Empty() {
				var ap TPMAuthPolicy
				var seq cryptobyte.String
				if !policy.ReadASN1Element(&seq, cryptobyte_asn1.SEQUENCE) {
					return nil, errors.New("malformed TSS2 authPolicy")
				}
				var name cryptobyte.String
				if !seq.ReadOptionalASN1(&name, &isPresent, cryptobyte_asn1.UTF8String) {
					return nil, errors.New("malformed TSS2 authPolicy name")
				}
				var policySeq cryptobyte.String
				if !seq.ReadASN1Element(&policySeq, cryptobyte_asn1.SEQUENCE) {
					return nil, errors.New("malformed TSS2 authPolicy policy")
				}
				if ap.Policy, err = readTPMPolicySequence(&policySeq); err != nil {
					return nil, errors.New("malformed TSS2 authPolicy policy")
				}
				key.AuthPolicy = append(key.AuthPolicy, ap)
			}
		}
	}

	if !input.ReadASN1Integer(&key.Parent) {
		return nil, errors.New("malformed TSS2 parent")
	}

	var ok bool
	if key.Pubkey, ok = readOctetString(&input); !ok {
		return nil, errors.New("malformed TSS2 pubkey")
	}

	if key.Privkey, ok = readOctetString(&input); !ok {
		return nil, errors.New("malformed TSS2 privkey")
	}

	return key, nil
}

func MarshalTSS2PrivateKey(key TPMKey) ([]byte, error) {
	return asn1.Marshal(key)
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
	var (
		ok       bool
		policies []TPMPolicy
	)
	for !input.Empty() {
		var p TPMPolicy
		var seq cryptobyte.String
		if !input.ReadASN1Element(&seq, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("malformed TSS2 policy")
		}
		if !seq.ReadASN1Integer(&p.CommandCode) {
			return nil, errors.New("malformed TSS2 policy commandCode")
		}
		if p.CommandPolicy, ok = readOctetString(&seq); ok {
			return nil, errors.New("malformed TSS2 policy commandPolicy")
		}
		policies = append(policies, p)
	}
	return policies, nil
}
