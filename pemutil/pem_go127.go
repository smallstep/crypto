//go:build go1.27

package pemutil

import (
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func serialize(in any) (*pem.Block, bool, error) {
	switch in.(type) {
	case *mldsa.PublicKey:
		b, err := x509.MarshalPKIXPublicKey(in)
		if err != nil {
			return nil, false, err
		}
		return &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		}, false, nil
	case *mldsa.PrivateKey:
		b, err := x509.MarshalPKCS8PrivateKey(in)
		if err != nil {
			return nil, false, err
		}
		return &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: b,
		}, true, nil
	default:
		return nil, false, fmt.Errorf("cannot serialize type '%T', value '%v'", in, in)
	}
}
