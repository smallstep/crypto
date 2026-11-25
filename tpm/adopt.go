package tpm

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"time"

	"github.com/smallstep/go-attestation/attest"

	internalkey "go.step.sm/crypto/tpm/internal/key"
	"go.step.sm/crypto/tpm/storage"
)

// ErrAdoptUnsupported is returned when adopting a key on a platform where
// keys are not persisted under a name, so there is no existing key to adopt.
// Only Windows persists them so.
var ErrAdoptUnsupported = errors.New("adopting an existing key is not supported on this platform")

// ErrKeyMismatch is returned when the key persisted under a name is not the
// key the caller expected to adopt.
var ErrKeyMismatch = errors.New("persisted key does not match the expected public key")

// AdoptKeyConfig is used to pass configuration when adopting a Key that is
// not to be attested.
type AdoptKeyConfig struct {
	// Public is the public key the adopted key must have, such as the one in
	// a certificate issued for it. It is required: the name alone does not
	// show the key is the one the caller means.
	Public crypto.PublicKey
	// MachineKey selects the local machine key store rather than the current
	// user's. See [CreateKeyConfig.MachineKey] for details.
	MachineKey bool
}

// AdoptAttestedKeyConfig is used to pass configuration when adopting a Key
// that is to be attested by an AK.
type AdoptAttestedKeyConfig struct {
	// Public is the public key the adopted key must have. See
	// [AdoptKeyConfig.Public].
	Public crypto.PublicKey
	// QualifyingData is passed to the TPM when the AK certifies the key, as
	// [AttestKeyConfig.QualifyingData] is.
	QualifyingData []byte
	// MachineKey selects the local machine key store rather than the current
	// user's. It must match the AK's scope, as for [TPM.AttestKey].
	MachineKey bool
}

// AdoptKey records a Key identified by `name` for a key the provider already
// persists under that name, rather than creating one. It is for a key whose
// record was lost while the key itself remained: [TPM.CreateKey] cannot take
// the name back, since the provider refuses to create a key over an existing
// one, and the key may still back a working credential.
//
// The persisted key must be one [TPM.CreateKey] could have created, and its
// public key must equal config.Public; otherwise [ErrKeyMismatch] or another
// error is returned and nothing is recorded. If a Key with the same name is
// already recorded, [ErrExists] is returned. The Key won't be attested by an
// AK. Only Windows persists keys under a name; elsewhere
// [ErrAdoptUnsupported] is returned.
func (t *TPM) AdoptKey(ctx context.Context, name string, config AdoptKeyConfig) (key *Key, err error) {
	expected, err := expectedPublic(name, config.Public)
	if err != nil {
		return nil, err
	}

	if err = t.open(ctx, openOptions{machineKey: config.MachineKey}); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	now := time.Now()
	if err := t.ensureUnrecorded(name); err != nil {
		return nil, err
	}

	data, pub, err := internalkey.Adopt(prefixKey(name), internalkey.AdoptConfig{MachineKey: config.MachineKey})
	if err != nil {
		if errors.Is(err, internalkey.ErrAdoptUnsupported) {
			return nil, ErrAdoptUnsupported
		}
		return nil, fmt.Errorf("failed adopting key %q: %w", name, err)
	}
	if !expected.Equal(pub) {
		return nil, fmt.Errorf("failed adopting key %q: %w", name, ErrKeyMismatch)
	}

	key = &Key{
		name:       name,
		data:       data,
		createdAt:  now,
		machineKey: config.MachineKey,
		tpm:        t,
	}

	if err := t.store.AddKey(key.toStorage()); err != nil {
		return nil, fmt.Errorf("failed adding key %q to storage: %w", name, err)
	}
	if err := t.store.Persist(); err != nil {
		return nil, fmt.Errorf("failed persisting key %q to storage: %w", name, err)
	}

	return
}

// AdoptAttestedKey is [TPM.AdoptKey] for a key that is attested by the AK
// identified by `akName`: the AK certifies the adopted key against
// config.QualifyingData, as [TPM.AttestKey] certifies a key it creates, and
// the Key is recorded as attested by it.
//
// Certification is TPM2_Certify over the persisted key, the command
// [TPM.AttestKey] runs on the key it has just created, so it proves the same
// thing: the key is resident in the TPM the AK belongs to.
func (t *TPM) AdoptAttestedKey(ctx context.Context, akName, name string, config AdoptAttestedKeyConfig) (key *Key, err error) {
	expected, err := expectedPublic(name, config.Public)
	if err != nil {
		return nil, err
	}

	if err = t.open(ctx, openOptions{machineKey: config.MachineKey}); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	now := time.Now()
	if err := t.ensureUnrecorded(name); err != nil {
		return nil, err
	}

	ak, err := t.store.GetAK(akName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed getting AK %q: %w", akName, ErrNotFound)
		}
		return nil, fmt.Errorf("failed getting AK %q: %w", akName, err)
	}
	if config.MachineKey != ak.MachineKey {
		return nil, fmt.Errorf("AdoptAttestedKeyConfig.MachineKey=%v does not match AK %q scope (MachineKey=%v); attested keys inherit their AK's scope", config.MachineKey, akName, ak.MachineKey)
	}

	loadedAK, err := t.attestTPM.LoadAK(ak.Data)
	if err != nil {
		return nil, fmt.Errorf("failed loading AK %q: %w", akName, err)
	}
	defer loadedAK.Close(t.attestTPM)

	akey, err := t.attestTPM.AdoptKey(loadedAK, &attest.KeyConfig{
		Name:           prefixKey(name),
		QualifyingData: config.QualifyingData,
	})
	if err != nil {
		if errors.Is(err, attest.ErrAdoptUnsupported) {
			return nil, ErrAdoptUnsupported
		}
		return nil, fmt.Errorf("failed adopting key %q: %w", name, err)
	}
	defer akey.Close()

	if !expected.Equal(akey.Public()) {
		return nil, fmt.Errorf("failed adopting key %q: %w", name, ErrKeyMismatch)
	}

	data, err := akey.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling key %q: %w", name, err)
	}

	key = &Key{
		name:       name,
		data:       data,
		attestedBy: akName,
		createdAt:  now,
		machineKey: ak.MachineKey,
		tpm:        t,
	}

	if err := t.store.AddKey(key.toStorage()); err != nil {
		return nil, fmt.Errorf("failed adding key %q to storage: %w", name, err)
	}
	if err := t.store.Persist(); err != nil {
		return nil, fmt.Errorf("failed persisting key %q: %w", name, err)
	}

	return
}

// expectedPublic checks the arguments every adoption needs: a name, since
// the key is found by it, and a public key that can be compared.
func expectedPublic(name string, pub crypto.PublicKey) (comparablePublicKey, error) {
	if name == "" {
		return nil, errors.New("adopting a key requires its name")
	}
	if pub == nil {
		return nil, fmt.Errorf("adopting key %q requires the public key it must have", name)
	}
	expected, ok := pub.(comparablePublicKey)
	if !ok {
		return nil, fmt.Errorf("adopting key %q: public key of type %T cannot be compared", name, pub)
	}
	return expected, nil
}

// ensureUnrecorded returns [ErrExists] when a Key named name is recorded.
func (t *TPM) ensureUnrecorded(name string) error {
	_, err := t.store.GetKey(name)
	switch {
	case err == nil:
		return fmt.Errorf("failed adopting key %q: %w", name, ErrExists)
	case errors.Is(err, storage.ErrNotFound):
		return nil
	default:
		return fmt.Errorf("failed adopting key %q: %w", name, err)
	}
}
