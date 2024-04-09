package tpm

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/smallstep/go-attestation/attest"
	internalkey "go.step.sm/crypto/tpm/internal/key"
	"go.step.sm/crypto/tpm/storage"
)

// Key models a TPM 2.0 Key. A Key can be used
// to sign data. When a Key is created, it can be
// attested by an AK, to be able to prove that it
// was created by a specific TPM.
type Key struct {
	name       string
	data       []byte
	attestedBy string
	chain      []*x509.Certificate
	createdAt  time.Time
	blobs      *Blobs
	tpm        *TPM
}

// Name returns the Key name. The name uniquely
// identifies the Key if a TPM with persistent
// storage is used.
func (k *Key) Name() string {
	return k.name
}

// Data returns the Key data blob. The data blob
// contains all information required for the Key
// to be loaded into the TPM that created it again,
// so that it can be used for signing data.
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

// MarshalJSON marshals the Key to JSON.
func (k *Key) MarshalJSON() ([]byte, error) {
	chain := make([][]byte, len(k.chain))
	for i, cert := range k.chain {
		chain[i] = cert.Raw
	}
	o := struct {
		Name       string    `json:"name"`
		Data       []byte    `json:"data"`
		AttestedBy string    `json:"attestedBy,omitempty"`
		Chain      [][]byte  `json:"chain,omitempty"`
		CreatedAt  time.Time `json:"createdAt"`
	}{
		Name:       k.name,
		Data:       k.data,
		AttestedBy: k.attestedBy,
		Chain:      chain,
		CreatedAt:  k.createdAt,
	}
	return json.Marshal(o)
}

// comparablePublicKey is an interface that allows a crypto.PublicKey to be
// compared to another crypto.PublicKey.
type comparablePublicKey interface {
	Equal(crypto.PublicKey) bool
}

// CreateKeyConfig is used to pass configuration
// when creating Keys.
type CreateKeyConfig struct {
	// Algorithm to be used, either RSA or ECDSA.
	Algorithm string
	// Size is used to specify the bit size of the key or elliptic curve. For
	// example, '256' is used to specify curve P-256.
	Size int

	// TODO(hs): move key name to this struct?
}

// AttestKeyConfig is used to pass configuration
// when creating Keys that are to be attested by
// an AK.
type AttestKeyConfig struct {
	// Algorithm to be used, either RSA or ECDSA.
	Algorithm string
	// Size is used to specify the bit size of the key or elliptic curve. For
	// example, '256' is used to specify curve P-256.
	Size int
	// QualifyingData is additional data that is passed to the TPM.
	// It can be used as a nonce to ensure freshness of an attestation.
	// When used with ACME `device-attest-01`, this contains a hash of
	// the key authorization.
	QualifyingData []byte

	// TODO(hs): add akName and key name to this struct?
}

// CreateKey creates a new Key identified by `name`. If no name is  provided,
// a random 10 character name is generated. If a Key with the same name exists,
// `ErrExists` is returned. The Key won't be attested by an AK.
func (t *TPM) CreateKey(ctx context.Context, name string, config CreateKeyConfig) (key *Key, err error) {
	if err = t.open(goTPMCall(ctx)); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	now := time.Now()
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
	if err := t.validate(&createConfig); err != nil {
		return nil, fmt.Errorf("invalid key creation parameters: %w", err)
	}
	data, err := internalkey.Create(t.rwc, prefixKey(name), createConfig)
	if err != nil {
		return nil, fmt.Errorf("failed creating key %q: %w", name, err)
	}

	key = &Key{
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

	return
}

type attestValidationWrapper attest.KeyConfig

func (w attestValidationWrapper) Validate() error {
	switch w.Algorithm {
	case "RSA":
		if w.Size > 2048 {
			return fmt.Errorf("%d bits RSA keys are (currently) not supported in go.step.sm/crypto; maximum is 2048", w.Size)
		}
	case "ECDSA":
		break
	default:
		return fmt.Errorf("unsupported algorithm %q", w.Algorithm)
	}
	return nil
}

// AttestKey creates a new Key identified by `name` and attested by the AK
// identified by `akName`. If no name is  provided, a random 10 character
// name is generated. If a Key with the same name exists, `ErrExists` is
// returned.
func (t *TPM) AttestKey(ctx context.Context, akName, name string, config AttestKeyConfig) (key *Key, err error) {
	if err = t.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

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

	keyConfig := attest.KeyConfig{
		Algorithm:      attest.Algorithm(config.Algorithm),
		Size:           config.Size,
		QualifyingData: config.QualifyingData,
		Name:           prefixKey(name),
	}
	if err := t.validate(attestValidationWrapper(keyConfig)); err != nil {
		return nil, fmt.Errorf("invalid key attestation parameters: %w", err)
	}
	akey, err := t.attestTPM.NewKey(loadedAK, &keyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed creating key %q: %w", name, err)
	}
	defer akey.Close()

	data, err := akey.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling key %q: %w", name, err)
	}

	key = &Key{
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

	return
}

// GetKey returns the Key identified by `name`. It returns `ErrNotfound`
// if it doesn't exist.
func (t *TPM) GetKey(ctx context.Context, name string) (key *Key, err error) {
	if err = t.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	skey, err := t.store.GetKey(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed getting key %q: %w", name, ErrNotFound)
		}
		return nil, fmt.Errorf("failed getting key %q: %w", name, err)
	}

	return keyFromStorage(skey, t), nil
}

// ListKeys returns a slice of Keys. The result is (currently)
// not ordered.
func (t *TPM) ListKeys(ctx context.Context) (keys []*Key, err error) {
	if err = t.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	skeys, err := t.store.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed listing keys: %w", err)
	}

	keys = make([]*Key, 0, len(skeys))
	for _, skey := range skeys {
		keys = append(keys, keyFromStorage(skey, t))
	}

	return
}

// GetKeysAttestedBy returns a slice of Keys attested by the AK
// identified by `akName`. The result is (currently) not ordered.
func (t *TPM) GetKeysAttestedBy(ctx context.Context, akName string) (keys []*Key, err error) {
	if err = t.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	skeys, err := t.store.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed listing keys: %w", err)
	}

	keys = make([]*Key, 0, len(skeys))
	for _, skey := range skeys {
		if skey.AttestedBy == akName {
			keys = append(keys, keyFromStorage(skey, t))
		}
	}

	return
}

// DeleteKey removes the Key identified by `name`. It returns `ErrNotfound`
// if it doesn't exist.
func (t *TPM) DeleteKey(ctx context.Context, name string) (err error) {
	if err := t.open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

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

	return
}

// Signer returns a crypto.Signer backed by the Key.
func (k *Key) Signer(ctx context.Context) (crypto.Signer, error) {
	return k.tpm.GetSigner(ctx, k.name)
}

// CertificationParameters returns information about the key that can be used to
// verify key certification.
func (k *Key) CertificationParameters(ctx context.Context) (params attest.CertificationParameters, err error) {
	if err = k.tpm.open(ctx); err != nil {
		return params, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, k.tpm, &err)

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
func (k *Key) Blobs(ctx context.Context) (blobs *Blobs, err error) {
	if k.blobs != nil {
		return k.blobs, nil
	}

	if err = k.tpm.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, k.tpm, &err)

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

	return k.blobs, nil
}

// SetCertificateChain associates an X.509 certificate chain with the Key.
// If the public key doesn't match the public key in the first certificate
// in the chain (the leaf), an error is returned.
func (k *Key) SetCertificateChain(ctx context.Context, chain []*x509.Certificate) (err error) {
	if err = k.tpm.open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, k.tpm, &err)

	signer, err := k.Signer(internalCall(ctx)) // TODO: cache the crypto.PublicKey after its first load instead?
	if err != nil {
		return fmt.Errorf("failed getting signer for key: %w", err)
	}

	if len(chain) > 0 {
		leaf := chain[0]
		leafPK, ok := leaf.PublicKey.(crypto.PublicKey)
		if !ok {
			return fmt.Errorf("unexpected type for certificate public key: %T", leaf.PublicKey)
		}

		publicKey, ok := leafPK.(comparablePublicKey)
		if !ok {
			return errors.New("certificate public key can't be compared to a crypto.PublicKey")
		}

		if !publicKey.Equal(signer.Public()) {
			return errors.New("public key does not match the leaf certificate public key")
		}
	}

	k.chain = chain // TODO(hs): deep copy, so that certs can't be changed by pointer?

	if err := k.tpm.store.UpdateKey(k.toStorage()); err != nil {
		return fmt.Errorf("failed updating key %q: %w", k.name, err)
	}

	return
}

// toStorage transforms the Key to the struct used for
// persisting Keys.
func (k *Key) toStorage() *storage.Key {
	return &storage.Key{
		Name:       k.name,
		Data:       k.data,
		AttestedBy: k.attestedBy,
		Chain:      k.chain,
		CreatedAt:  k.createdAt.UTC(),
	}
}

// keyFromStorage recreates a Key from the struct used for
// persisting Keys.
func keyFromStorage(sk *storage.Key, t *TPM) *Key {
	return &Key{
		name:       sk.Name,
		data:       sk.Data,
		attestedBy: sk.AttestedBy,
		chain:      sk.Chain,
		createdAt:  sk.CreatedAt.Local(),
		tpm:        t,
	}
}
