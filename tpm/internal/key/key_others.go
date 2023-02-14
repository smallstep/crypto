//go:build !windows
// +build !windows

package key

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"go.step.sm/crypto/tpm/internal/open"
)

func create(deviceName, keyName string, config CreateConfig) ([]byte, error) {
	rwc, err := open.TPM(deviceName)
	if err != nil {
		return nil, fmt.Errorf("error opening TPM: %w", err)
	}
	defer rwc.Close()

	srk, _, err := getPrimaryKeyHandle(rwc, commonSrkEquivalentHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get SRK handle: %w", err)
	}

	tmpl, err := templateFromConfig(&KeyConfig{Algorithm: Algorithm(config.Algorithm), Size: config.Size})
	if err != nil {
		return nil, fmt.Errorf("incorrect key options: %w", err)
	}

	blob, pub, creationData, _, _, err := tpm2.CreateKey(rwc, srk, tpm2.PCRSelection{}, "", "", tmpl)
	if err != nil {
		return nil, fmt.Errorf("CreateKey() failed: %w", err)
	}

	out := serializedKey{
		Encoding:   keyEncodingEncrypted,
		TPMVersion: uint8(2), // hardcoded to not import github.com/google/go-attestation/attest
		Name:       keyName,
		Public:     pub,
		Blob:       blob,
		CreateData: creationData,
	}

	return out.Serialize()
}
