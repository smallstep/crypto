package skae

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"github.com/ryboe/q"

	"github.com/google/go-attestation/attest"
)

var (
	oidSubjectKeyAttestationEvidence = asn1.ObjectIdentifier{2, 23, 133, 6, 1, 1} // SKAE (Subject Key Attestation Evidence) OID: 2.23.133.6.1.1
	oidAuthorityInfoAccessOcsp       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

func CreateSubjectKeyAttestationEvidenceExtension(akCert *x509.Certificate, params attest.CertificationParameters, shouldEncrypt bool) (pkix.Extension, error) {
	asn1Issuer, err := asn1.Marshal(akCert.Issuer.ToRDNSequence())
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("error marshaling issuer: %w", err)
	}

	skaeExtension := asn1SKAE{
		TCGSpecVersion:         asn1TCGSpecVersion{Major: 2, Minor: 0},
		KeyAttestationEvidence: asn1KeyAttestationEvidence{},
	}

	attestationEvidence := asn1AttestationEvidence{
		TPMCertifyInfo: asn1TPMCertifyInfo{
			CertifyInfo: asn1.BitString{ // TODO: check if setting the values like this is correct
				Bytes:     params.CreateAttestation,
				BitLength: len(params.CreateAttestation) * 8,
			},
			Signature: asn1.BitString{
				Bytes:     params.CreateSignature,
				BitLength: len(params.CreateSignature) * 8,
			},
		},
		TPMIdentityCredAccessInfo: asn1TPMIdentityCredentialAccessInfo{
			AuthorityInfoAccess: createAIA(akCert),
			IssuerSerial: issuerAndSerial{
				IssuerName:   asn1.RawValue{FullBytes: asn1Issuer},
				SerialNumber: akCert.SerialNumber,
			},
		},
	}

	aeb, err := asn1.Marshal(attestationEvidence)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("error marshaling attestation evidence: %w", err)
	}

	q.Q(base64.StdEncoding.EncodeToString(aeb))

	if !shouldEncrypt {
		//skaeExtension.KeyAttestationEvidence.AttestEvidence = attestationEvidence
		skaeExtension.KeyAttestationEvidence.Evidence = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Tag:        0, // CHOICE "0"
			Bytes:      aeb,
		}
	} else {
		// TODO: encrypt the AttestEvidence to (right) recipient; set it as the EnvelopedAttestEvidence
		encryptedAEB := aeb

		eae := asn1EnvelopedAttestationEvidence{
			RecipientInfos: []recipientInfo{}, // TODO: fill recipient(s)
			EncryptedAttestInfo: asn1EncryptedAttestationInfo{
				EncryptionAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: nil, // TODO: select and fill
				},
				EncryptedAttestEvidence: encryptedAEB,
			},
		}

		eaeBytes, err := asn1.Marshal(eae)
		if err != nil {
			return pkix.Extension{}, errors.New("error marshaling EnvelopedAttestationEvidence")
		}

		skaeExtension.KeyAttestationEvidence.Evidence = asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Tag:        1, // CHOICE "1"
			Bytes:      eaeBytes,
		}

		return pkix.Extension{}, errors.New("encrypting the AttestEvidence is not yet supported")
	}

	skaeExtensionBytes, err := asn1.Marshal(skaeExtension)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("creating SKAE extension failed: %w", err)
	}

	result := pkix.Extension{
		Id:       oidSubjectKeyAttestationEvidence,
		Critical: false, // non standard extension; don't break clients
		Value:    skaeExtensionBytes,
	}

	q.Q(result)
	q.Q(string(result.Value))
	q.Q(base64.StdEncoding.EncodeToString(result.Value))

	b, err := asn1.Marshal(result)
	if err != nil {
		return result, err
	}

	q.Q(base64.StdEncoding.EncodeToString(b))

	return result, nil
}

func createAIA(ak *x509.Certificate) []asn1AuthorityInfoAccessSyntax {
	var aiaValues []asn1AuthorityInfoAccessSyntax
	for _, server := range ak.OCSPServer {
		aiaValues = append(aiaValues, asn1AuthorityInfoAccessSyntax{
			Method:   oidAuthorityInfoAccessOcsp,
			Location: asn1.RawValue{Tag: asn1.TagOID, Class: asn1.ClassContextSpecific, Bytes: []byte(server)},
		})
	}
	for _, url := range ak.IssuingCertificateURL {
		aiaValues = append(aiaValues, asn1AuthorityInfoAccessSyntax{
			Method:   oidAuthorityInfoAccessIssuers,
			Location: asn1.RawValue{Tag: asn1.TagOID, Class: asn1.ClassContextSpecific, Bytes: []byte(url)},
		})
	}
	return aiaValues
}

type asn1SKAE struct {
	TCGSpecVersion         asn1TCGSpecVersion
	KeyAttestationEvidence asn1KeyAttestationEvidence
}

type asn1TCGSpecVersion struct {
	Major int
	Minor int
}

type asn1KeyAttestationEvidence struct {
	// AttestEvidence          asn1AttestationEvidence // TODO: ASN1 CHOICE between those two
	// EnvelopedAttestEvidence asn1EnvelopedAttestationEvidence
	Evidence asn1.RawValue
}

type asn1AttestationEvidence struct {
	TPMCertifyInfo            asn1TPMCertifyInfo
	TPMIdentityCredAccessInfo asn1TPMIdentityCredentialAccessInfo
}

type asn1TPMCertifyInfo struct {
	CertifyInfo asn1.BitString
	Signature   asn1.BitString
}

type asn1TPMIdentityCredentialAccessInfo struct {
	AuthorityInfoAccess []asn1AuthorityInfoAccessSyntax
	IssuerSerial        issuerAndSerial
}

type asn1AuthorityInfoAccessSyntax struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type asn1EnvelopedAttestationEvidence struct {
	RecipientInfos      []recipientInfo `asn1:"set"`
	EncryptedAttestInfo asn1EncryptedAttestationInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type asn1EncryptedAttestationInfo struct {
	EncryptionAlgorithm     pkix.AlgorithmIdentifier
	EncryptedAttestEvidence []byte // -- The ciphertext resulting from the encryption of DER-encoded AttestationEvidence (against public key in recipientinfo; something like that)
}
