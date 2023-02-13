package tpm

import (
	"context"
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/go-attestation/attest"
	"go.step.sm/crypto/tpm/internal/key"
	"go.step.sm/crypto/tpm/storage"
)

type Key struct {
	Name       string
	Data       []byte
	AttestedBy string
	CreatedAt  time.Time

	tpm *TPM
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

func (t *TPM) CreateKey(ctx context.Context, name string, config CreateKeyConfig) (Key, error) {

	result := Key{}
	if err := t.Open(ctx); err != nil {
		return result, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx, false)

	now := time.Now()

	if name == "" {
		nameHex := make([]byte, 5)
		if n, err := rand.Read(nameHex); err != nil || n != len(nameHex) {
			return result, fmt.Errorf("rand.Read() failed with %d/%d bytes read and error: %v", n, len(nameHex), err)
		}
		name = fmt.Sprintf("%x", nameHex)
	}

	prefixedKeyName := fmt.Sprintf("app-%s", name)

	createConfig := key.CreateConfig{
		Algorithm: string(config.Algorithm),
		Size:      config.Size,
	}
	data, err := key.Create(t.deviceName, prefixedKeyName, createConfig)
	if err != nil {
		return result, fmt.Errorf("failed creating key: %w", err)
	}

	storedKey := &storage.Key{
		Name:      name,
		Data:      data,
		CreatedAt: now,
	}

	if err := t.store.AddKey(storedKey); err != nil {
		return result, fmt.Errorf("error adding key to storage: %w", err)
	}

	if err := t.store.Persist(); err != nil {
		return result, fmt.Errorf("error persisting to storage: %w", err)
	}

	return Key{Name: storedKey.Name, Data: storedKey.Data, CreatedAt: now, tpm: t}, nil
}

// TODO: every interaction with the actual TPM now opens the "connection" when required, then
// closes it when the operation is done. Can we reuse one open "connection" to the TPM for
// multiple operations reliably? What makes it harder is that now all operations are implemented
// by go-attestation, so it might come down to replicating a lot of that logic. It could involve
// checking multiple locks and/or pointers and instantiating when required. Opening and closing
// on-demand is the simplest way and safe to do for now, though.
func (t *TPM) AttestKey(ctx context.Context, akName, name string, config AttestKeyConfig) (Key, error) {

	result := Key{}
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

	ak, err := t.store.GetAK(akName)
	if err != nil {
		return result, fmt.Errorf("error getting AK %q: %w", akName, err)
	}

	loadedAK, err := at.LoadAK(ak.Data)
	if err != nil {
		return result, fmt.Errorf("error loading AK %q: %w", akName, err)
	}
	defer loadedAK.Close(at)

	if name == "" {
		nameHex := make([]byte, 5)
		if n, err := rand.Read(nameHex); err != nil || n != len(nameHex) {
			return result, fmt.Errorf("rand.Read() failed with %d/%d bytes read and error: %v", n, len(nameHex), err)
		}
		name = fmt.Sprintf("%x", nameHex)
	}

	prefixedKeyName := fmt.Sprintf("app-%s", name)

	keyConfig := &attest.KeyConfig{
		Algorithm:      attest.Algorithm(config.Algorithm),
		Size:           config.Size,
		QualifyingData: config.QualifyingData,
		Name:           prefixedKeyName,
	}

	key, err := at.NewKey(loadedAK, keyConfig)
	if err != nil {
		return result, fmt.Errorf("error creating key: %w", err)
	}
	defer key.Close()

	data, err := key.Marshal()
	if err != nil {
		return result, fmt.Errorf("error marshaling key: %w", err)
	}

	storedKey := &storage.Key{
		Name:       name,
		Data:       data,
		AttestedBy: akName,
		CreatedAt:  now,
	}

	if err := t.store.AddKey(storedKey); err != nil {
		return result, fmt.Errorf("error adding key to storage: %w", err)
	}

	if err := t.store.Persist(); err != nil {
		return result, fmt.Errorf("error persisting to storage: %w", err)
	}

	return Key{Name: storedKey.Name, Data: storedKey.Data, AttestedBy: akName, CreatedAt: now, tpm: t}, nil
}

func (t *TPM) GetKey(ctx context.Context, name string) (Key, error) {

	result := Key{}
	if err := t.Open(ctx); err != nil {
		return result, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx, false)

	key, err := t.store.GetKey(name)
	if err != nil {
		return result, fmt.Errorf("error getting Key %q: %w", name, err)
	}

	return Key{Name: key.Name, Data: key.Data, AttestedBy: key.AttestedBy, CreatedAt: key.CreatedAt, tpm: t}, nil
}

func (t *TPM) ListKeys(ctx context.Context) ([]Key, error) {

	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx, false)

	keys, err := t.store.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("error listing keys: %w", err)
	}

	result := make([]Key, 0, len(keys))
	for _, key := range keys {
		result = append(result, Key{Name: key.Name, Data: key.Data, AttestedBy: key.AttestedBy, CreatedAt: key.CreatedAt, tpm: t})
	}

	return result, nil
}

func (t *TPM) DeleteKey(ctx context.Context, name string) error {
	if err := t.Open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx, false)

	at, err := attest.OpenTPM(t.attestConfig)
	if err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	key, err := t.store.GetKey(name)
	if err != nil {
		return fmt.Errorf("failed loading key: %w", err)
	}

	// TODO: catch case when named key isn't found; tpm.GetKey returns nil in that case,
	// resulting in a nil pointer. Need an ErrNotFound like type from the storage layer and appropriate
	// handling?
	if err := at.DeleteKey(key.Data); err != nil {
		return fmt.Errorf("failed deleting key: %w", err)
	}

	if err := t.store.DeleteKey(name); err != nil {
		return fmt.Errorf("error deleting key from storage: %w", err)
	}

	if err := t.store.Persist(); err != nil {
		return fmt.Errorf("error persisting storage: %w", err)
	}

	return nil
}

// signer implements crypto.Signer backed by a TPM key
type signer struct {
	tpm    *TPM
	key    Key
	public crypto.PublicKey
}

func (s *signer) Public() crypto.PublicKey {
	return s.public
}

func (s *signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	ctx := context.Background()
	if err := s.tpm.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer s.tpm.Close(ctx, false)

	at, err := attest.OpenTPM(s.tpm.attestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	loadedKey, err := at.LoadKey(s.key.Data)
	if err != nil {
		return nil, err
	}
	defer loadedKey.Close()

	priv, err := loadedKey.Private(s.public)
	if err != nil {
		return nil, err
	}

	var signer crypto.Signer
	var ok bool
	if signer, ok = priv.(crypto.Signer); !ok {
		return nil, errors.New("error getting TPM private key as crypto.Signer")
	}

	return signer.Sign(rand, digest, opts)
}

// GetSigner returns a crypto.Signer for a TPM key identified by name.
func (t *TPM) GetSigner(ctx context.Context, name string) (crypto.Signer, error) {

	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx, false)

	at, err := attest.OpenTPM(t.attestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	key, err := t.store.GetKey(name)
	if err != nil {
		return nil, err
	}

	loadedKey, err := at.LoadKey(key.Data)
	if err != nil {
		return nil, err
	}
	defer loadedKey.Close()

	return &signer{
		tpm:    t,
		key:    Key{Name: name, Data: key.Data, AttestedBy: key.AttestedBy, CreatedAt: key.CreatedAt, tpm: t},
		public: loadedKey.Public(),
	}, nil
}

// Signer returns a crypto.Signer backed by the Key
func (k Key) Signer(ctx context.Context) (crypto.Signer, error) {
	return k.tpm.GetSigner(ctx, k.Name)
}

// CertificationParameters returns information about the key that can be used to
// verify key certification.
func (k Key) CertificationParameters(ctx context.Context) (params attest.CertificationParameters, err error) {
	if err := k.tpm.Open(ctx); err != nil {
		return params, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer k.tpm.Close(ctx, false)

	at, err := attest.OpenTPM(k.tpm.attestConfig)
	if err != nil {
		return params, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer at.Close()

	loadedKey, err := at.LoadKey(k.Data)
	if err != nil {
		return attest.CertificationParameters{}, fmt.Errorf("failed loading key: %w", err)
	}
	defer loadedKey.Close()

	params = loadedKey.CertificationParameters()

	return
}
