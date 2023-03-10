package storage

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"
)

type AK struct {
	Name      string
	Data      []byte
	Chain     []*x509.Certificate
	CreatedAt time.Time
}

func (ak *AK) MarshalJSON() ([]byte, error) {
	chain := make([][]byte, len(ak.Chain))
	for i, cert := range ak.Chain {
		chain[i] = cert.Raw
	}

	sak := serializedAK{
		Name:      ak.Name,
		Type:      typeAK,
		Data:      ak.Data,
		CreatedAt: ak.CreatedAt,
	}

	if len(chain) > 0 {
		sak.Chain = chain
	}

	return json.Marshal(sak)
}

func (ak *AK) UnmarshalJSON(data []byte) error {
	sak := &serializedAK{}
	if err := json.Unmarshal(data, sak); err != nil {
		return fmt.Errorf("failed unmarshaling serialized AK: %w", err)
	}

	ak.Name = sak.Name
	ak.Data = sak.Data
	ak.CreatedAt = sak.CreatedAt

	if len(sak.Chain) > 0 {
		chain := make([]*x509.Certificate, len(sak.Chain))
		for i, certBytes := range sak.Chain {
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return fmt.Errorf("failed parsing certificate: %w", err)
			}
			chain[i] = cert
		}
		ak.Chain = chain
	}

	return nil
}

type Key struct {
	Name       string
	Data       []byte
	AttestedBy string
	Chain      []*x509.Certificate
	CreatedAt  time.Time
}

func (key *Key) MarshalJSON() ([]byte, error) {
	chain := make([][]byte, len(key.Chain))
	for i, cert := range key.Chain {
		chain[i] = cert.Raw
	}

	sk := serializedKey{
		Name:       key.Name,
		Type:       typeKey,
		Data:       key.Data,
		AttestedBy: key.AttestedBy,
		CreatedAt:  key.CreatedAt,
	}

	if len(chain) > 0 {
		sk.Chain = chain
	}

	return json.Marshal(sk)
}

func (key *Key) UnmarshalJSON(data []byte) error {
	sk := &serializedKey{}
	if err := json.Unmarshal(data, sk); err != nil {
		return fmt.Errorf("failed unmarshaling serialized key: %w", err)
	}

	key.Name = sk.Name
	key.Data = sk.Data
	key.AttestedBy = sk.AttestedBy
	key.CreatedAt = sk.CreatedAt

	if len(sk.Chain) > 0 {
		chain := make([]*x509.Certificate, len(sk.Chain))
		for i, certBytes := range sk.Chain {
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return fmt.Errorf("failed parsing certificate: %w", err)
			}
			chain[i] = cert
		}
		key.Chain = chain
	}

	return nil
}

const (
	akPrefix  = "ak-"
	keyPrefix = "key-"
)

type tpmObjectType string

const (
	typeAK  tpmObjectType = "AK"
	typeKey tpmObjectType = "KEY"
)

type serializedAK struct {
	Name      string        `json:"name"`
	Type      tpmObjectType `json:"type"`
	Data      []byte        `json:"data"`
	Chain     [][]byte      `json:"chain"`
	CreatedAt time.Time     `json:"createdAt"`
}

type serializedKey struct {
	Name       string        `json:"name"`
	Type       tpmObjectType `json:"type"`
	Data       []byte        `json:"data"`
	AttestedBy string        `json:"attestedBy"`
	Chain      [][]byte      `json:"chain"`
	CreatedAt  time.Time     `json:"createdAt"`
}

func keyForKey(name string) string {
	return fmt.Sprintf("%s%s", keyPrefix, name)
}

func keyForAK(name string) string {
	return fmt.Sprintf("%s%s", akPrefix, name)
}
