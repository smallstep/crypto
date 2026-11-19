package tpmkms

import (
	"context"
	"errors"
	"fmt"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/tpm"
)

// AdoptKey records an application key the provider already persists under
// the name the URI gives, rather than creating one, and returns it as
// [TPMKMS.CreateKey] returns a key it creates. It is for a key whose record
// was lost while the key itself remained, which CreateKey cannot take back
// since the provider refuses to create a key over an existing one.
//
// The URI takes the properties [TPMKMS.CreateKey] takes for an application
// key: name, attest-by, qualifying-data, key-scope and tss2. Algorithm and size
// are not taken: the key already exists.
//
// With attest-by, the AK certifies the adopted key against qualifying-data,
// as it certifies a key CreateKey creates. The key's public key must equal
// req.PublicKey; otherwise [tpm.ErrKeyMismatch] is returned, wrapped, and
// nothing is recorded. A key already recorded under the name is an
// [apiv1.AlreadyExistsError]. Only Windows persists keys under a name;
// elsewhere [tpm.ErrAdoptUnsupported] is returned, wrapped.
//
// # Experimental
//
// Notice: This method is EXPERIMENTAL and may be changed or removed in a later
// release.
func (k *TPMKMS) AdoptKey(req *apiv1.AdoptKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, errors.New("AdoptKeyRequest 'name' cannot be empty")
	}

	properties, err := parseNameURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("failed parsing %q: %w", req.Name, err)
	}
	if properties.ak {
		return nil, errors.New("adopting an AK is not supported")
	}

	ctx := context.Background()
	machineKey := properties.isMachineKey()

	var key *tpm.Key
	if properties.attestBy != "" {
		key, err = k.tpm.AdoptAttestedKey(ctx, properties.attestBy, properties.name, tpm.AdoptAttestedKeyConfig{
			Public:         req.PublicKey,
			QualifyingData: properties.qualifyingData,
			MachineKey:     machineKey,
		})
	} else {
		key, err = k.tpm.AdoptKey(ctx, properties.name, tpm.AdoptKeyConfig{
			Public:     req.PublicKey,
			MachineKey: machineKey,
		})
	}
	if err != nil {
		if errors.Is(err, tpm.ErrExists) {
			return nil, apiv1.AlreadyExistsError{Message: err.Error()}
		}
		return nil, fmt.Errorf("failed adopting key: %w", err)
	}

	return keyResponse(ctx, key, properties, machineKey)
}
