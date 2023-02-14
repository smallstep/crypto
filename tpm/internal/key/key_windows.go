//go:build windows
// +build windows

package key

import (
	"fmt"
)

func create(_, keyName string, config CreateConfig) ([]byte, error) {

	pcp, err := openPCP()
	if err != nil {
		return nil, fmt.Errorf("failed to open PCP: %w", err)
	}
	defer pcp.Close()

	hnd, pub, blob, err := pcp.NewKey(keyName, &KeyConfig{Algorithm: Algorithm(config.Algorithm), Size: config.Size})
	if err != nil {
		return nil, fmt.Errorf("pcp failed to mint application key: %v", err)
	}

	_, _ = hnd, blob

	// tpmPub, err := tpm2.DecodePublic(pub)
	// if err != nil {
	// 	return nil, fmt.Errorf("decode public key: %v", err)
	// }

	// pubKey, err := tpmPub.Key()
	// if err != nil {
	// 	return nil, fmt.Errorf("access public key: %v", err)
	// }

	out := serializedKey{
		Encoding:   keyEncodingOSManaged,
		TPMVersion: uint8(2), // hardcoded to not import github.com/google/go-attestation/attest
		Name:       keyName,
		Public:     pub,
	}

	return out.Serialize()
}