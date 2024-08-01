package tpm

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/smallstep/go-attestation/attest"
	x509ext "github.com/smallstep/go-attestation/x509"

	"go.step.sm/crypto/tpm/storage"
)

// AK models a TPM 2.0 Attestation Key. An AK can be used
// to attest the creation of a Key. Attestation Keys are
// restricted, meaning that they can only sign data generated
// by the TPM.
type AK struct {
	name         string
	data         []byte
	chain        []*x509.Certificate
	createdAt    time.Time
	blobs        *Blobs
	attestParams *attest.AttestationParameters
	tpm          *TPM
}

// Name returns the AK name. The name uniquely
// identifies an AK if a TPM with persistent
// storage is used.
func (ak *AK) Name() string {
	return ak.name
}

// Data returns the AK data blob. The data blob
// contains all information required for the AK
// to be loaded into the TPM that created it again,
// so that it can be used for attesting new keys.
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
// It can return an empty chain if the AK public key
// has not been certified yet.
func (ak *AK) CertificateChain() []*x509.Certificate {
	return ak.chain
}

// Public returns the AK public key. This is backed
// by a call to the TPM, so it can fail. If it fails,
// nil is returned.
//
// TODO: see improvement described in the private method
// to always return a non-nil crypto.PublicKey.
func (ak *AK) Public() crypto.PublicKey {
	pub, err := ak.public(context.Background())
	if err != nil {
		return nil
	}
	return pub
}

// public returns the AK public key. This can fail, because
// retrieval relies on the TPM.
//
// It is currently not exported, because I don't like that it
// currently requires a context to be passed. See the TODO
// below for a way to prevent that from being needed.
//
// TODO(hs): we could (de)serialize the attestation parameters or
// just the AK public key bytes, so that no TPM interaction is
// required. The attestation parameters don't change after an
// AK has been created. There's only no hard guarantee that the
// AK is used with the same TPM as the one it was created by.
// Generally that shouldn't be an issue, though. It would be nice
// if we would do the same for Keys in that case. An equivalent
// of `ParseAKPublic` for Keys would be great for that.
func (ak *AK) public(ctx context.Context) (crypto.PublicKey, error) {
	ap, err := ak.AttestationParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed getting AK attestation parameters: %w", err)
	}

	akp, err := attest.ParseAKPublic(attest.TPMVersion20, ap.Public)
	if err != nil {
		return nil, fmt.Errorf("failed parsing AK public data: %w", err)
	}

	return akp.Public, nil
}

// MarshalJSON marshals the AK to JSON.
func (ak *AK) MarshalJSON() ([]byte, error) {
	chain := make([][]byte, len(ak.chain))
	for i, cert := range ak.chain {
		chain[i] = cert.Raw
	}
	o := struct {
		Name      string    `json:"name"`
		Data      []byte    `json:"data"`
		Chain     [][]byte  `json:"chain,omitempty"`
		CreatedAt time.Time `json:"createdAt"`
	}{
		Name:      ak.name,
		Data:      ak.data,
		Chain:     chain,
		CreatedAt: ak.createdAt,
	}
	return json.Marshal(o)
}

// CreateAK creates and stores a new AK identified by `name`.
// If no name is  provided, a random 10 character name is generated.
// If an AK with the same name exists, `ErrExists` is returned.
func (t *TPM) CreateAK(ctx context.Context, name string) (ak *AK, err error) {
	if err = t.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

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
	aak, err := t.attestTPM.NewAK(&akConfig)
	if err != nil {
		return nil, fmt.Errorf("failed creating AK %q: %w", name, err)
	}
	defer aak.Close(t.attestTPM)

	data, err := aak.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed marshaling AK %q: %w", name, err)
	}

	ak = &AK{
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

// GetAK returns the AK identified by `name`. It returns `ErrNotfound`
// if it doesn't exist.
func (t *TPM) GetAK(ctx context.Context, name string) (ak *AK, err error) {
	if err = t.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	sak, err := t.store.GetAK(name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("failed getting AK %q: %w", name, ErrNotFound)
		}
		return nil, fmt.Errorf("failed getting AK %q: %w", name, err)
	}

	return akFromStorage(sak, t), nil
}

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// GetAKByPermanentIdentifier returns an AK for which a certificate
// exists with `permanentIdentifier` as one of the Subject Alternative
// Names. It returns `ErrNotFound` if it doesn't exist.
func (t *TPM) GetAKByPermanentIdentifier(ctx context.Context, permanentIdentifier string) (ak *AK, err error) {
	if err = t.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	aks, err := t.ListAKs(internalCall(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed listing AKs: %w", err)
	}

	// loop through all available AKs and check if one exist that
	// contains a Subject Alternative Name extension containing the
	// requested PermanentIdentifier.
	for _, ak = range aks {
		if ak.HasValidPermanentIdentifier(permanentIdentifier) {
			return
		}
	}

	return nil, ErrNotFound
}

// ListAKs returns a slice of AKs. The result is (currently)
// not ordered.
func (t *TPM) ListAKs(ctx context.Context) (aks []*AK, err error) {
	if err := t.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

	saks, err := t.store.ListAKs()
	if err != nil {
		return nil, fmt.Errorf("failed listing AKs: %w", err)
	}

	aks = make([]*AK, 0, len(aks))
	for _, sak := range saks {
		aks = append(aks, akFromStorage(sak, t))
	}

	// TODO: include ordering by name or createdAt?

	return
}

// DeleteAK removes the AK identified by `name`. It returns `ErrNotfound`
// if it doesn't exist. Keys that were attested by the AK have to be removed
// before removing the AK, otherwise an error will be returned.
func (t *TPM) DeleteAK(ctx context.Context, name string) (err error) {
	if err := t.open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, t, &err)

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
		return fmt.Errorf("failed deleting AK %q because %d key(s) exist that were attested by it", name, len(keys))
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

	return
}

// AttestationParameters returns information about the AK, typically used to
// generate a credential activation challenge.
func (ak *AK) AttestationParameters(ctx context.Context) (params attest.AttestationParameters, err error) {
	if ak.attestParams != nil {
		return *ak.attestParams, nil
	}

	if err = ak.tpm.open(ctx); err != nil {
		return params, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, ak.tpm, &err)

	loadedAK, err := ak.tpm.attestTPM.LoadAK(ak.data)
	if err != nil {
		return params, fmt.Errorf("failed loading AK %q: %w", ak.name, err)
	}
	defer loadedAK.Close(ak.tpm.attestTPM)

	params = loadedAK.AttestationParameters()
	ak.attestParams = &params

	return
}

// EncryptedCredential represents encrypted parameters which must be activated
// against a key.
type EncryptedCredential attest.EncryptedCredential

// ActivateCredential decrypts the secret using the key to prove that the AK was
// generated on the same TPM as the EK. This operation is synonymous with
// TPM2_ActivateCredential.
func (ak *AK) ActivateCredential(ctx context.Context, in EncryptedCredential) (secret []byte, err error) {
	if err := ak.tpm.open(ctx); err != nil {
		return secret, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, ak.tpm, &err)

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
func (ak *AK) Blobs(ctx context.Context) (blobs *Blobs, err error) {
	if ak.blobs != nil {
		return ak.blobs, nil
	}

	if err = ak.tpm.open(ctx); err != nil {
		return nil, fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, ak.tpm, &err)

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

	return ak.blobs, nil
}

// SetCertificateChain associates an X.509 certificate chain with the AK.
// If the AK public key doesn't match the public key in the first certificate
// in the chain (the leaf), an error is returned.
func (ak *AK) SetCertificateChain(ctx context.Context, chain []*x509.Certificate) (err error) {
	if err := ak.tpm.open(ctx); err != nil {
		return fmt.Errorf("failed opening TPM: %w", err)
	}
	defer closeTPM(ctx, ak.tpm, &err)

	akPublic, err := ak.public(internalCall(ctx))
	if err != nil {
		return fmt.Errorf("failed getting AK public key: %w", err)
	}

	if len(chain) > 0 {
		leaf := chain[0]
		leafPK, ok := leaf.PublicKey.(crypto.PublicKey)
		if !ok {
			return fmt.Errorf("unexpected type for AK certificate public key: %T", leaf.PublicKey)
		}

		publicKey, ok := leafPK.(comparablePublicKey)
		if !ok {
			return errors.New("certificate public key can't be compared to a crypto.PublicKey")
		}

		if !publicKey.Equal(akPublic) {
			return errors.New("AK public key does not match the leaf certificate public key")
		}
	}

	ak.chain = chain // TODO(hs): deep copy, so that certs can't be changed by pointer?

	if err := ak.tpm.store.UpdateAK(ak.toStorage()); err != nil {
		return fmt.Errorf("failed updating AK %q: %w", ak.name, err)
	}

	return
}

// HasValidPermanentIdentifier indicates if the AK has a certificate
// with the `permanentIdentifier` as one of its Subject Alternative
// Names.
func (ak *AK) HasValidPermanentIdentifier(permanentIdentifier string) bool {
	chain := ak.chain
	if len(chain) == 0 {
		return false
	}
	akCert := chain[0]

	// TODO(hs): before continuing, add check if the cert is still valid?

	var sanExtension pkix.Extension
	for _, ext := range akCert.Extensions {
		if ext.Id.Equal(oidSubjectAlternativeName) {
			sanExtension = ext
			break
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

// toStorage transforms the AK to the struct used for
// persisting AKs.
func (ak *AK) toStorage() *storage.AK {
	return &storage.AK{
		Name:      ak.name,
		Data:      ak.data,
		Chain:     ak.chain,
		CreatedAt: ak.createdAt.UTC(),
	}
}

// akFromStorage recreates an AK from the struct used for
// persisting AKs.
func akFromStorage(sak *storage.AK, t *TPM) *AK {
	return &AK{
		name:      sak.Name,
		data:      sak.Data,
		chain:     sak.Chain,
		createdAt: sak.CreatedAt.Local(),
		tpm:       t,
	}
}
