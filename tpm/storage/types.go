package storage

import (
	"crypto/x509"
	"fmt"
	"time"
)

type AK struct {
	Name      string
	Data      []byte
	Chain     []*x509.Certificate
	CreatedAt time.Time
}

type Key struct {
	Name       string
	Data       []byte
	AttestedBy string
	Chain      []*x509.Certificate
	CreatedAt  time.Time
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
