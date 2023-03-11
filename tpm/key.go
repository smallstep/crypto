package tpm

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-attestation/attest"
	internalkey "go.step.sm/crypto/tpm/internal/key"
	"go.step.sm/crypto/tpm/storage"
)

// Key models a TPM 2.0 Key.
type Key struct {
	name       string
	data       []byte
	attestedBy string
	chain      []*x509.Certificate
	createdAt  time.Time
	blobs      *Blobs
	tpm        *TPM
}

// Name returns the Key name.
func (k *Key) Name() string {
	return k.name
}

// Data returns the Key data blob.
func (k *Key) Data() []byte {
	return k.data
}

// AttestedBy returns the name of the AK the Key was
// attested (certified) by at creation time.
func (k *Key) AttestedBy() string {
	return k.attestedBy
}

// WasAttested returns whether or not the Key was
// attested (certified) by an AK at creation time.
func (k *Key) WasAttested() bool {
	return k.attestedBy != ""
}

// WasAttestedBy returns whether or not the Key
// was attested (certified) by the provided AK
// at creation time.
func (k *Key) WasAttestedBy(ak *AK) bool {
	return k.attestedBy == ak.name
}

// Certificate returns the certificate for the Key, if set.
// Will return nil in case no AK certificate is available.
func (k *Key) Certificate() *x509.Certificate {
	if len(k.chain) == 0 {
		return nil
	}
	return k.chain[0]
}

// CertificateChain returns the certificate chain for the Key.
// It can return an empty chain.
func (k *Key) CertificateChain() []*x509.Certificate {
	return k.chain
}

// CreatedAt returns the the creation time of the Key.
func (k *Key) CreatedAt() time.Time {
	return k.createdAt.Truncate(time.Second)
}

func (k *Key) MarshalJSON() ([]byte, error) {
	type out struct {
		Name       string    `json:"name"`
		Data       []byte    `json:"data"`
		AttestedBy string    `json:"attestedBy,omitempty"`
		Chain      [][]byte  `json:"chain,omitempty"`
		CreatedAt  time.Time `json:"createdAt"`
	}
	chain := make([][]byte, len(k.chain))
	for i, cert := range k.chain {
		chain[i] = cert.Raw
	}
	o := out{
		Name:       k.name,
		Data:       k.data,
		AttestedBy: k.attestedBy,
		Chain:      chain,
		CreatedAt:  k.createdAt,
	}
	return json.Marshal(o)
}

type CreateKeyConfig struct {
	// Algorithm to be used, either RSA or ECDSA.
	Algorithm string
	// Size is used to specify the bit size of the key or elliptic curve. For
	// example, '256' is used to specify curve P-256.
	Size int

	// TODO(hs): move key name to this struct?
}

type AttestKeyConfig struct {
	// Algorithm to be used, either RSA or ECDSA.
	Algorithm string
	// Size is used to specify the bit size of the key or elliptic curve. For
	// example, '256' is used to specify curve P-256.
	Size int

	QualifyingData []byte

	// TODO(hs): add akName and key name to this struct?
}

func (t *TPM) CreateKey(ctx context.Context, name string, config CreateKeyConfig) (*Key, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	now := time.Now()

	var err error
	if name, err = processName(name); err != nil {
		return nil, err
	}

	if _, err := t.store.GetKey(name); err == nil {
		return nil, fmt.Errorf("failed creating key %q: %w", name, ErrExists)
	}

	createConfig := internalkey.CreateConfig{
		Algorithm: config.Algorithm,
		Size:      config.Size,
	}
	data, err := internalkey.Create(t.rwc, prefixKey(name), createConfig)
	if err != nil {
		return nil, fmt.Errorf("failed creating key %q: %w", name, err)
	}

	key := &Key{
		name:      name,
		data:      data,
		createdAt: now,
		tpm:       t,
	}

	if err := t.store.AddKey(key.toStorage()); err != nil {
		return nil, fmt.Errorf("failed adding key %q to storage: %w", name, err)
	}

	if err := t.store.Persist(); err != nil {
		return nil, fmt.Errorf("failed persisting key %q to storage: %w", name, err)
	}

	return key, nil
}

// TODO: every interaction with the actual TPM now opens the "connection" when required, then
// closes it when the operation is done. Can we reuse one open "connection" to the TPM for
// multiple operations reliably? What makes it harder is that now all operations are implemented
// by go-attestation, so it might come down to replicating a lot of that logic. It could involve
// checking multiple locks and/or pointers and instantiating when required. Opening and closing
// on-demand is the simplest way and safe to do for now, though.
func (t *TPM) AttestKey(ctx context.Context, akName, name string, config AttestKeyConfig) (*Key, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	var err error
	now := time.Now()
	if name, err = processName(name); err != nil {
		return nil, err
	}

	if _, err := t.store.GetKey(name); err == nil {
		return nil, fmt.Errorf("failed creating key %q: %w", name, ErrExists)
	}

	ak, err := t.store.GetAK(akName)
	if err != nil {
		return nil, fmt.Errorf("failed getting AK %q: %w", akName, err)
	}

	loadedAK, err := t.attestTPM.LoadAK(ak.Data)
	if err != nil {
		return nil, fmt.Errorf("failed loading AK %q: %w", akName, err)
	}
	defer loadedAK.Close(t.attestTPM)

	keyConfig := &attest.KeyConfig{
		Algorithm:      attest.Algorithm(config.Algorithm),
		Size:           config.Size,
		QualifyingData: config.QualifyingData,
		Name:           prefixKey(name),
	}

	akey, err := t.attestTPM.NewKey(loadedAK, keyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed creating key %q: %w", name, err)
	}
	defer akey.Close()

	data, err := akey.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling key %q: %w", name, err)
	}

	key := &Key{
		name:       name,
		data:       data,
		attestedBy: akName,
		createdAt:  now,
		tpm:        t,
	}

	if err := t.store.AddKey(key.toStorage()); err != nil {
		return nil, fmt.Errorf("failed adding key %q to storage: %w", name, err)
	}

	if err := t.store.Persist(); err != nil {
		return nil, fmt.Errorf("failed persisting key %q: %w", name, err)
	}

	return key, nil
}

func (t *TPM) GetKey(ctx context.Context, name string) (*Key, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	key, err := t.store.GetKey(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed getting key %q: %w", name, ErrNotFound)
		}
		return nil, fmt.Errorf("failed getting key %q: %w", name, err)
	}

	return keyFromStorage(key, t), nil
}

func (t *TPM) ListKeys(ctx context.Context) ([]*Key, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	keys, err := t.store.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed listing keys: %w", err)
	}

	result := make([]*Key, 0, len(keys))
	for _, key := range keys {
		result = append(result, keyFromStorage(key, t))
	}

	return result, nil
}

func (t *TPM) GetKeysAttestedBy(ctx context.Context, akName string) ([]*Key, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	keys, err := t.store.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed listing keys: %w", err)
	}

	result := make([]*Key, 0, len(keys))
	for _, key := range keys {
		if key.AttestedBy == akName {
			result = append(result, keyFromStorage(key, t))
		}
	}

	return result, nil
}

func (t *TPM) DeleteKey(ctx context.Context, name string) error {
	if err := t.Open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	key, err := t.store.GetKey(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("failed getting key %q: %w", name, ErrNotFound)
		}
		return fmt.Errorf("failed getting key %q: %w", name, err)
	}

	if err := t.attestTPM.DeleteKey(key.Data); err != nil {
		return fmt.Errorf("failed deleting key %q: %w", name, err)
	}

	if err := t.store.DeleteKey(name); err != nil {
		return fmt.Errorf("failed deleting key %q from storage: %w", name, err)
	}

	if err := t.store.Persist(); err != nil {
		return fmt.Errorf("failed persisting storage: %w", err)
	}

	return nil
}

// Signer returns a crypto.Signer backed by the Key.
func (k *Key) Signer(ctx context.Context) (crypto.Signer, error) {
	return k.tpm.GetSigner(ctx, k.name)
}

// CertificationParameters returns information about the key that can be used to
// verify key certification.
func (k *Key) CertificationParameters(ctx context.Context) (params attest.CertificationParameters, err error) {
	if err := k.tpm.Open(ctx); err != nil {
		return params, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer k.tpm.Close(ctx)

	loadedKey, err := k.tpm.attestTPM.LoadKey(k.data)
	if err != nil {
		return attest.CertificationParameters{}, fmt.Errorf("failed loading key %q: %w", k.name, err)
	}
	defer loadedKey.Close()

	params = loadedKey.CertificationParameters()

	return
}

// Blobs returns a container for the private and public key blobs.
// The resulting blobs are compatible with tpm2-tools, so can be used
// like this (after having been written to key.priv and key.pub):
//
//	tpm2_load -C 0x81000001 -u key.pub -r key.priv -c key.ctx
func (k *Key) Blobs(ctx context.Context) (*Blobs, error) {
	if k.blobs == nil {
		if err := k.tpm.Open(ctx); err != nil {
			return nil, fmt.Errorf("failed opening TPM: %w", err)
		}
		defer k.tpm.Close(ctx)

		key, err := k.tpm.attestTPM.LoadKey(k.data)
		if err != nil {
			return nil, fmt.Errorf("failed loading key: %w", err)
		}
		defer key.Close()

		public, private, err := key.Blobs()
		if err != nil {
			return nil, fmt.Errorf("failed getting key blobs: %w", err)
		}
		k.setBlobs(private, public)
	}

	return k.blobs, nil
}

func (k *Key) SetCertificateChain(ctx context.Context, chain []*x509.Certificate) error {
	if err := k.tpm.Open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer k.tpm.Close(ctx)

	// TODO(hs): perform validation, such as check if the chain includes leaf for the
	// AK public key?

	k.chain = chain // TODO(hs): deep copy, so that certs can't be changed by pointer?

	if err := k.tpm.store.UpdateKey(k.toStorage()); err != nil {
		return fmt.Errorf("failed updating key %q: %w", k.name, err)
	}

	return nil
}

func (k *Key) toStorage() *storage.Key {
	return &storage.Key{
		Name:       k.name,
		Data:       k.data,
		AttestedBy: k.attestedBy,
		Chain:      k.chain,
		CreatedAt:  k.createdAt,
	}
}

func keyFromStorage(sk *storage.Key, t *TPM) *Key {
	return &Key{
		name:       sk.Name,
		data:       sk.Data,
		attestedBy: sk.AttestedBy,
		chain:      sk.Chain,
		createdAt:  sk.CreatedAt,
		tpm:        t,
	}
}
