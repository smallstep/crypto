//go:build windows
// +build windows

//nolint:errorlint,revive // copied code from github.com/google/go-attestation
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
		return nil, fmt.Errorf("pcp failed to mint application key: %w", err)
	}

	_, _ = hnd, blob

	out := serializedKey{
		Encoding:   keyEncodingOSManaged,
		TPMVersion: uint8(2), // hardcoded to not import github.com/google/go-attestation/attest
		Name:       keyName,
		Public:     pub,
	}

	return out.Serialize()
}
