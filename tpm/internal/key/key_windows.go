//go:build windows

package key

import (
	"fmt"
	"io"
)

func create(_ io.ReadWriteCloser, keyName string, config CreateConfig) ([]byte, error) {
	pcp, err := openPCP()
	if err != nil {
		return nil, fmt.Errorf("failed to open PCP: %w", err)
	}
	defer pcp.Close()

	_, pub, _, err := pcp.NewKey(keyName, &KeyConfig{Algorithm: Algorithm(config.Algorithm), Size: config.Size})
	if err != nil {
		return nil, fmt.Errorf("pcp failed to mint application key: %w", err)
	}

	out := serializedKey{
		Encoding:   keyEncodingOSManaged,
		TPMVersion: uint8(2), // hardcoded to not import github.com/google/go-attestation/attest
		Name:       keyName,
		Public:     pub,
	}

	return out.Serialize()
}
