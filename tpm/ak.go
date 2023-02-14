package tpm

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/google/go-attestation/attest"

	"go.step.sm/crypto/tpm/storage"
)

type AK struct {
	Name      string
	Data      []byte
	CreatedAt time.Time

	tpm *TPM
}

func (t *TPM) CreateAK(ctx context.Context, name string) (AK, error) {
	result := AK{}
	if err := t.Open(ctx); err != nil {
		return result, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx, false)

	at, err := attest.OpenTPM(t.attestConfig)
	if err != nil {
		return result, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	now := time.Now()

	if name == "" {
		// TODO: decouple the TPM key name from the name recorded in the storage? This might
		// make it easier to work with the key names as a user; the TPM key name would be abstracted
		// away. The key name in the storage can be different from the key stored with the key (which,
		// to be far, isn't even used on Linux TPMs)
		nameHex := make([]byte, 5)
		if n, err := rand.Read(nameHex); err != nil || n != len(nameHex) {
			return result, fmt.Errorf("rand.Read() failed with %d/%d bytes read and error: %w", n, len(nameHex), err)
		}
		name = fmt.Sprintf("%x", nameHex)
	}

	prefixedName := fmt.Sprintf("ak-%s", name)

	akConfig := attest.AKConfig{
		Name: prefixedName,
	}
	ak, err := at.NewAK(&akConfig)
	if err != nil {
		return result, err
	}
	defer ak.Close(at)

	data, err := ak.Marshal()
	if err != nil {
		return result, err
	}

	storedAK := &storage.AK{
		Name:      name,
		Data:      data,
		CreatedAt: now,
	}

	if err := t.store.AddAK(storedAK); err != nil {
		return result, err
	}

	if err := t.store.Persist(); err != nil {
		return result, err
	}

	return AK{Name: storedAK.Name, Data: storedAK.Data, CreatedAt: now, tpm: t}, nil
}

func (t *TPM) GetAK(ctx context.Context, name string) (AK, error) {
	result := AK{}
	if err := t.Open(ctx); err != nil {
		return result, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx, false)

	ak, err := t.store.GetAK(name)
	if err != nil {
		return result, fmt.Errorf("error getting AK %q: %w", name, err)
	}

	return AK{Name: ak.Name, Data: ak.Data, CreatedAt: ak.CreatedAt, tpm: t}, nil
}

func (t *TPM) ListAKs(ctx context.Context) ([]AK, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx, false)

	aks, err := t.store.ListAKs()
	if err != nil {
		return nil, fmt.Errorf("error listing AKs: %w", err)
	}

	result := make([]AK, 0, len(aks))
	for _, ak := range aks {
		result = append(result, AK{Name: ak.Name, Data: ak.Data, CreatedAt: ak.CreatedAt, tpm: t})
	}

	return result, nil
}

func (t *TPM) DeleteAK(ctx context.Context, name string) error {
	if err := t.Open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx, false)

	at, err := attest.OpenTPM(t.attestConfig)
	if err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	ak, err := t.store.GetAK(name)
	if err != nil {
		return fmt.Errorf("failed loading AK: %w", err)
	}

	// TODO: catch case when named AK isn't found; tpm.GetAK returns nil in that case,
	// resulting in a nil pointer. Need an ErrNotFound like type from the storage layer and appropriate
	// handling?
	if err := at.DeleteKey(ak.Data); err != nil {
		return fmt.Errorf("failed deleting AK: %w", err)
	}

	if err := t.store.DeleteAK(name); err != nil {
		return fmt.Errorf("error deleting AK from storage: %w", err)
	}

	if err := t.store.Persist(); err != nil {
		return fmt.Errorf("error persisting storage: %w", err)
	}

	return nil
}

// AttestationParameters returns information about the AK, typically used to
// generate a credential activation challenge.
func (ak AK) AttestationParameters(ctx context.Context) (params attest.AttestationParameters, err error) {
	if err := ak.tpm.Open(ctx); err != nil {
		return params, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer ak.tpm.Close(ctx, false)

	at, err := attest.OpenTPM(ak.tpm.attestConfig)
	if err != nil {
		return params, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	loadedAK, err := at.LoadAK(ak.Data)
	if err != nil {
		return params, fmt.Errorf("failed loading AK: %w", err)
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
func (ak AK) ActivateCredential(ctx context.Context, in EncryptedCredential) (secret []byte, err error) {
	if err := ak.tpm.Open(ctx); err != nil {
		return secret, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer ak.tpm.Close(ctx, false)

	at, err := attest.OpenTPM(ak.tpm.attestConfig)
	if err != nil {
		return secret, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	loadedAK, err := at.LoadAK(ak.Data)
	if err != nil {
		return secret, fmt.Errorf("failed loading AK: %w", err)
	}
	defer loadedAK.Close(at)

	secret, err = loadedAK.ActivateCredential(at, attest.EncryptedCredential(in))

	return
}
