package key

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/google/go-tpm/legacy/tpm2"
)

// ErrAdoptUnsupported is returned by Adopt on platforms where keys are not
// persisted under a name, so there is no existing key to adopt.
var ErrAdoptUnsupported = errors.New("adopting an existing key is not supported on this platform")

// AdoptConfig configures Adopt.
type AdoptConfig struct {
	// MachineKey selects the local machine key store rather than the current
	// user's, as [CreateConfig.MachineKey] does on creation.
	MachineKey bool
}

// Adopt returns the serialized representation of a key already persisted
// under keyName, in the same format Create returns for a key it creates, and
// the key's public key as the TPM holds it. It is for a key whose serialized
// representation was lost while the key itself remained.
//
// The key must have the attributes of a key Create makes (see
// [CheckAdoptable]). Only Windows persists keys under a name; elsewhere Adopt
// returns ErrAdoptUnsupported.
func Adopt(keyName string, config AdoptConfig) ([]byte, crypto.PublicKey, error) {
	return adopt(keyName, config)
}

// adoptableAttributes are the attributes of every key Create makes: generated
// in the TPM, unable to leave it, and able to sign.
const adoptableAttributes = tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagSign

// CheckAdoptable reports why pub is not a key Adopt may take over: one whose
// attributes differ from those of a key Create makes.
func CheckAdoptable(pub tpm2.Public) error {
	if pub.Attributes&adoptableAttributes != adoptableAttributes {
		return fmt.Errorf("attributes %#x lack fixedTPM, fixedParent, sensitiveDataOrigin or sign", uint32(pub.Attributes))
	}
	if pub.Attributes&tpm2.FlagRestricted != 0 {
		return fmt.Errorf("attributes %#x mark a restricted key, such as an AK", uint32(pub.Attributes))
	}
	return nil
}
