package tpm

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-attestation/attest"
	x509ext "github.com/google/go-attestation/x509"

	"go.step.sm/crypto/tpm/storage"
)

// AK models a TPM 2.0 Attestation Key.
type AK struct {
	name      string
	data      []byte
	chain     []*x509.Certificate
	createdAt time.Time
	blobs     *Blobs
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
	return ak.createdAt.Truncate(time.Second)
}

// Certificate returns the AK certificate, if set.
// Will return nil in case no AK certificate is available.
func (ak *AK) Certificate() *x509.Certificate {
	if len(ak.chain) == 0 {
		return nil
	}
	return ak.chain[0]
}

// CertificateChain returns the AK certificate chain.
// It can return an empty chain.
func (ak *AK) CertificateChain() []*x509.Certificate {
	return ak.chain
}

func (ak *AK) MarshalJSON() ([]byte, error) {
	type out struct {
		Name      string    `json:"name"`
		Data      []byte    `json:"data"`
		Chain     [][]byte  `json:"chain,omitempty"`
		CreatedAt time.Time `json:"createdAt"`
	}
	chain := make([][]byte, len(ak.chain))
	for i, cert := range ak.chain {
		chain[i] = cert.Raw
	}
	o := out{
		Name:      ak.name,
		Data:      ak.data,
		Chain:     chain,
		CreatedAt: ak.createdAt,
	}
	return json.Marshal(o)
}

func (t *TPM) CreateAK(ctx context.Context, name string) (*AK, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	now := time.Now()
	var err error
	if name, err = processName(name); err != nil {
		return nil, err
	}

	if _, err := t.store.GetAK(name); err == nil {
		return nil, fmt.Errorf("failed creating AK %q: %w", name, ErrExists)
	}

	akConfig := attest.AKConfig{
		Name: prefixAK(name),
	}
	aak, err := t.attestTPM.NewAK(&akConfig)
	if err != nil {
		return nil, fmt.Errorf("failed creating new AK %q: %w", name, err)
	}
	defer aak.Close(t.attestTPM)

	data, err := aak.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling AK %q: %w", name, err)
	}

	ak := &AK{
		name:      name,
		data:      data,
		createdAt: now,
		tpm:       t,
	}

	if err := t.store.AddAK(ak.toStorage()); err != nil {
		return nil, fmt.Errorf("failed adding AK %q: %w", name, err)
	}

	if err := t.store.Persist(); err != nil {
		return nil, fmt.Errorf("failed persisting AK %q: %w", name, err)
	}

	return ak, nil
}

func (t *TPM) GetAK(ctx context.Context, name string) (*AK, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	ak, err := t.store.GetAK(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed getting AK %q: %w", name, ErrNotFound)
		}
		return nil, fmt.Errorf("failed getting AK %q: %w", name, err)
	}

	return akFromStorage(ak, t), nil
}

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

func (t *TPM) GetAKByPermanentIdentifier(ctx context.Context, permanentIdentifier string) (*AK, error) {
	if err := t.Open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	aks, err := t.ListAKs(internalCall(ctx))
	if err != nil {
		return nil, err
	}

	// loop through all available AKs and check if one exist that
	// contains a Subject Alternative Name extension containing the
	// requested PermanentIdentifier.
	for _, ak := range aks {
		if ak.HasValidPermanentIdentifier(permanentIdentifier) {
			return ak, nil
		}
	}

	return nil, ErrNotFound
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
		result = append(result, akFromStorage(ak, t))
	}

	// TODO: include ordering by name or createdAt?

	return result, nil
}

func (t *TPM) DeleteAK(ctx context.Context, name string) error {
	if err := t.Open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer t.Close(ctx)

	ak, err := t.store.GetAK(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("failed getting AK %q: %w", name, ErrNotFound)
		}
		return fmt.Errorf("failed getting AK %q: %w", name, err)
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

	if err := t.attestTPM.DeleteKey(ak.Data); err != nil { // TODO: we could add a DeleteAK to go-attestation; under the hood it's loaded the same as a key though.
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

	loadedAK, err := ak.tpm.attestTPM.LoadAK(ak.data)
	if err != nil {
		return params, fmt.Errorf("failed loading AK %q: %w", ak.name, err)
	}
	defer loadedAK.Close(ak.tpm.attestTPM)

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

	loadedAK, err := ak.tpm.attestTPM.LoadAK(ak.data)
	if err != nil {
		return secret, fmt.Errorf("failed loading AK %q: %w", ak.name, err)
	}
	defer loadedAK.Close(ak.tpm.attestTPM)

	secret, err = loadedAK.ActivateCredential(ak.tpm.attestTPM, attest.EncryptedCredential(in))

	return
}

// Blobs returns a container for the private and public AK blobs.
// The resulting blobs are compatible with tpm2-tools, so can be used
// like this (after having been written to ak.priv and ak.pub):
//
//	tpm2_load -C 0x81000001 -u ak.pub -r ak.priv -c ak.ctx
func (ak *AK) Blobs(ctx context.Context) (*Blobs, error) {
	if ak.blobs == nil {
		if err := ak.tpm.Open(ctx); err != nil {
			return nil, fmt.Errorf("failed opening TPM: %w", err)
		}
		defer ak.tpm.Close(ctx)

		aak, err := ak.tpm.attestTPM.LoadAK(ak.data)
		if err != nil {
			return nil, fmt.Errorf("failed loading AK: %w", err)
		}
		defer aak.Close(ak.tpm.attestTPM)

		public, private, err := aak.Blobs()
		if err != nil {
			return nil, fmt.Errorf("failed getting AK blobs: %w", err)
		}
		ak.setBlobs(private, public)
	}

	return ak.blobs, nil
}

func (ak *AK) SetCertificateChain(ctx context.Context, chain []*x509.Certificate) error {
	if err := ak.tpm.Open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer ak.tpm.Close(ctx)

	// TODO(hs): perform validation, such as check if the chain includes leaf for the
	// AK public key?

	ak.chain = chain // TODO(hs): deep copy, so that certs can't be changed by pointer?

	if err := ak.tpm.store.UpdateAK(ak.toStorage()); err != nil {
		return fmt.Errorf("failed updating AK %q: %w", ak.name, err)
	}

	return nil
}

func (ak *AK) HasValidPermanentIdentifier(permanentIdentifier string) bool {
	chain := ak.chain
	if len(chain) == 0 {
		return false
	}
	akCert := chain[0]

	var sanExtension pkix.Extension
	for _, ext := range akCert.Extensions {
		if ext.Id.Equal(oidSubjectAlternativeName) {
			sanExtension = ext
		}
	}

	if sanExtension.Value == nil {
		return false
	}

	san, err := x509ext.ParseSubjectAltName(sanExtension) // TODO(hs): move to a package under our control?
	if err != nil {
		return false
	}

	// loop through the permanent identifier values and return
	// if the requested PermanentIdentifier was found.
	for _, p := range san.PermanentIdentifiers {
		if p.IdentifierValue == permanentIdentifier {
			return true
		}
	}

	return false
}

func (ak *AK) toStorage() *storage.AK {
	return &storage.AK{
		Name:      ak.name,
		Data:      ak.data,
		Chain:     ak.chain,
		CreatedAt: ak.createdAt,
	}
}

func akFromStorage(sak *storage.AK, t *TPM) *AK {
	return &AK{
		name:      sak.Name,
		data:      sak.Data,
		chain:     sak.Chain,
		createdAt: sak.CreatedAt,
		tpm:       t,
	}
}
