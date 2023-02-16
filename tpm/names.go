package tpm

import (
	"crypto/rand"
	"fmt"
)

func processName(name string) (string, error) {
	if name == "" {
		// TODO: decouple the TPM key name from the name recorded in the storage? This might
		// make it easier to work with the key names as a user; the TPM key name would be abstracted
		// away. The key name in the storage can be different from the key stored with the key (which,
		// to be far, isn't even used on Linux TPMs)
		nameHex := make([]byte, 5)
		if n, err := rand.Read(nameHex); err != nil || n != len(nameHex) {
			return "", fmt.Errorf("failed reading from CSPRNG: %w", err)
		}
		name = fmt.Sprintf("%x", nameHex)
	}

	return name, nil
}

// prefixAK prefixes `ak-` to the provided name.
//
// `ak-` is the default go-attestation uses for AKs.
func prefixAK(name string) string {
	return fmt.Sprintf("ak-%s", name)
}

// prefixKey prefixes `app-` to the provided name.
//
// `app-` is the default that go-attestation uses for Keys.
func prefixKey(name string) string {
	return fmt.Sprintf("app-%s", name)
}
