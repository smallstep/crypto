package tpm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-attestation/attest"

	"go.step.sm/crypto/tpm/storage"
)

// AK models a TPM 2.0 Attestation Key.
type AK struct {
	name      string
	data      []byte
	createdAt time.Time
	tpm       *TPM
}

// Name returns the AK name.
func (ak *AK) Name() string {
	return ak.name
}

// Data returns the AK data blob.
func (ak *AK) Data() []byte {
	return ak.data
}

// CreatedAt returns the creation time of the AK.
func (ak *AK) CreatedAt() time.Time {
	return ak.createdAt
}

func (ak *AK) MarshalJSON() ([]byte, error) {
	type out struct {
		Name      string    `json:"name"`
		Data      []byte    `json:"data"`
		CreatedAt time.Time `json:"createdAt"`
	}
	o := out{
		Name:      ak.name,
		Data:      ak.data,
		CreatedAt: ak.createdAt,
	}
	return json.Marshal(o)
}

func (t *TPM) CreateAK(ctx context.Context, name string) (*AK, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	at, err := attest.OpenTPM(t.attestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	now := time.Now()

	if name, err = processName(name); err != nil {
		return nil, err
	}

	if _, err := t.store.GetAK(name); err == nil {
		return nil, fmt.Errorf("failed creating AK %q: %w", name, ErrExists)
	}

	akConfig := attest.AKConfig{
		Name: prefixAK(name),
	}
	ak, err := at.NewAK(&akConfig)
	if err != nil {
		return nil, fmt.Errorf("failed creating new AK %q: %w", name, err)
	}
	defer ak.Close(at)

	data, err := ak.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling AK %q: %w", name, err)
	}

	storedAK := &storage.AK{
		Name:      name,
		Data:      data,
		CreatedAt: now,
	}

	if err := t.store.AddAK(storedAK); err != nil {
		return nil, fmt.Errorf("failed adding AK %q: %w", name, err)
	}

	if err := t.store.Persist(); err != nil {
		return nil, fmt.Errorf("failed persisting AK %q: %w", name, err)
	}

	return &AK{name: storedAK.Name, data: storedAK.Data, createdAt: now, tpm: t}, nil
}

func (t *TPM) GetAK(ctx context.Context, name string) (*AK, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	ak, err := t.store.GetAK(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed getting AK %q: %w", name, err)
	}

	return &AK{name: ak.Name, data: ak.Data, createdAt: ak.CreatedAt, tpm: t}, nil
}

func (t *TPM) ListAKs(ctx context.Context) ([]*AK, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	aks, err := t.store.ListAKs()
	if err != nil {
		return nil, fmt.Errorf("failed listing AKs: %w", err)
	}

	result := make([]*AK, 0, len(aks))
	for _, ak := range aks {
		result = append(result, &AK{name: ak.Name, data: ak.Data, createdAt: ak.CreatedAt, tpm: t})
	}

	return result, nil
}

func (t *TPM) DeleteAK(ctx context.Context, name string) error {
	if err := t.Open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	at, err := attest.OpenTPM(t.attestConfig)
	if err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	ak, err := t.store.GetAK(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("failed loading AK %q: %w", name, ErrNotFound)
		}
		return fmt.Errorf("failed loading AK %q: %w", name, err)
	}

	// prevent deleting the AK if the TPM (storage) contains keys that
	// were attested by it. While keys would still work if the AK were
	// deleted, some functionalities would no longer work. The AK can
	// only be deleted if all keys attested by it are deleted first.
	keys, err := t.GetKeysAttestedBy(internalCall(ctx), name)
	if err != nil {
		return fmt.Errorf("failed getting keys attested by AK %q: %w", name, err)
	}

	if len(keys) > 0 {
		return fmt.Errorf("cannot delete AK %q before deleting keys that were attested by it", name)
	}

	if err := at.DeleteKey(ak.Data); err != nil {
		return fmt.Errorf("failed deleting AK %q: %w", name, err)
	}

	if err := t.store.DeleteAK(name); err != nil {
		return fmt.Errorf("failed deleting AK %q from storage: %w", name, err)
	}

	if err := t.store.Persist(); err != nil {
		return fmt.Errorf("failed persisting storage: %w", err)
	}

	return nil
}

// AttestationParameters returns information about the AK, typically used to
// generate a credential activation challenge.
func (ak *AK) AttestationParameters(ctx context.Context) (params attest.AttestationParameters, err error) {
	if err := ak.tpm.Open(ctx); err != nil {
		return params, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer ak.tpm.Close(ctx)

	at, err := attest.OpenTPM(ak.tpm.attestConfig)
	if err != nil {
		return params, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	loadedAK, err := at.LoadAK(ak.data)
	if err != nil {
		return params, fmt.Errorf("failed loading AK %q: %w", ak.name, err)
	}
	defer loadedAK.Close(at)

	params = loadedAK.AttestationParameters()

	return
}

// EncryptedCredential represents encrypted parameters which must be activated
// against a key.
type EncryptedCredential attest.EncryptedCredential

// ActivateCredential decrypts the secret using the key to prove that the AK was
// generated on the same TPM as the EK. This operation is synonymous with
// TPM2_ActivateCredential.
func (ak *AK) ActivateCredential(ctx context.Context, in EncryptedCredential) (secret []byte, err error) {
	if err := ak.tpm.Open(ctx); err != nil {
		return secret, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer ak.tpm.Close(ctx)

	at, err := attest.OpenTPM(ak.tpm.attestConfig)
	if err != nil {
		return secret, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	loadedAK, err := at.LoadAK(ak.data)
	if err != nil {
		return secret, fmt.Errorf("failed loading AK %q: %w", ak.name, err)
	}
	defer loadedAK.Close(at)

	secret, err = loadedAK.ActivateCredential(at, attest.EncryptedCredential(in))

	return
}
