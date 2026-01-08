//go:build darwin && cgo && !nomackms

// Copyright (c) Smallstep Labs, Inc.
// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.
//
// Part of this code is based on
// https://github.com/facebookincubator/sks/blob/183e7561ecedc71992f23b2d37983d2948391f4c/macos/macos.go

package mackms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // required to calculate hash
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	cf "go.step.sm/crypto/internal/darwin/corefoundation"
	"go.step.sm/crypto/internal/darwin/security"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
)

// Scheme is the scheme used in uris, the string "mackms".
const Scheme = string(apiv1.MacKMS)

// DefaultTag is the default tag attribute (kSecAttrApplicationTag) added to all
// the keys.
var DefaultTag = "com.smallstep.crypto"

type keyAttributes struct {
	label            string
	tag              string
	hash             []byte
	retry            bool
	useSecureEnclave bool
	useBiometrics    bool
	sigAlgorithm     apiv1.SignatureAlgorithm
	keySize          int
}

// retryAttributes returns the original URI attributes used to get a private
// key, but only if they are different that the ones set. It will return nil, if
// they are the same. The only attribute that can change is the tag. This method
// would return the tag empty if it was set using the default value.
func (k *keyAttributes) retryAttributes() *keyAttributes {
	if !k.retry {
		return nil
	}
	return &keyAttributes{
		label:            k.label,
		hash:             k.hash,
		useSecureEnclave: k.useSecureEnclave,
		retry:            false,
	}
}

type keySearchAttributes struct {
	label            string
	tag              string
	hash             []byte
	secureEnclaveSet bool
	useSecureEnclave bool
}

type certAttributes struct {
	label                     string
	serialNumber              *big.Int
	keychain                  string
	useDataProtectionKeychain bool
}

type algorithmAttributes struct {
	Type string
	Size int
}

var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]algorithmAttributes{
	apiv1.UnspecifiedSignAlgorithm: {"EC", 256},
	apiv1.SHA256WithRSA:            {"RSA", 3072},
	apiv1.SHA384WithRSA:            {"RSA", 3072},
	apiv1.SHA512WithRSA:            {"RSA", 3072},
	apiv1.SHA256WithRSAPSS:         {"RSA", 3072},
	apiv1.SHA384WithRSAPSS:         {"RSA", 3072},
	apiv1.SHA512WithRSAPSS:         {"RSA", 3072},
	apiv1.ECDSAWithSHA256:          {"EC", 256},
	apiv1.ECDSAWithSHA384:          {"EC", 384},
	apiv1.ECDSAWithSHA512:          {"EC", 521},
}

// MacKMS is a key manager that uses keys stored in macOS Keychain or in the
// Secure Enclave.
//
// CreateKey methods can create keys with the following URIs:
//   - mackms:label=my-name
//   - mackms:label=my-name;tag=com.smallstep.crypto
//   - mackms;label=my-name;tag=
//   - mackms;label=my-name;se=true;bio=true
//
// GetPublicKey and CreateSigner accepts the above URIs as well as the following
// ones:
//   - my-name
//   - mackms:label=my-name;tag=com.smallstep.crypto;hash=ccb792f9d9a1262bfb814a339876f825bdba1261
//
// The above URIs support the following attributes:
//   - "label" corresponds with Apple's kSecAttrLabel. It is always required and
//     represents the key name. You will be able to see the keys in the Keychain,
//     looking for the value.
//   - "tag" corresponds with kSecAttrApplicationTag. It defaults to
//     com.smallstep.crypto. If tag is an empty string ("tag="), the attribute
//     will not be set.
//   - "se" is a boolean. If set to true, it will store the key in the
//     Secure Enclave. This option requires the application to be code-signed
//     with the appropriate entitlements.
//   - "bio" is a boolean value. If set to true, sign and verify operations
//     require Touch ID or Face ID. This options requires the key to be in the
//     Secure Enclave.
//   - "hash" corresponds with kSecAttrApplicationLabel. It is the SHA-1 of the
//     DER representation of an RSA public key using the PKCS #1 format or the
//     SHA-1 of the uncompressed ECDSA point according to SEC 1, Version 2.0,
//     Section 2.3.4.
type MacKMS struct {
	useDataProtectionKeychain bool
}

// New returns a new [MacKMS] instance. In code-signed applications, it is
// possible to initialize [MacKMS] with a URI that specifies whether to use the
// Data Protection Keychain for loading and storing certificates by default.
//
// The [New] function accepts the following URI format:
//   - mackms:keychain=dataProtection
func New(_ context.Context, opts apiv1.Options) (*MacKMS, error) {
	var useDataProtectionKeychain bool
	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, err
		}
		useDataProtectionKeychain = isDataProtectionKeychain(u.Get("keychain"), false)
	}

	return &MacKMS{
		useDataProtectionKeychain: useDataProtectionKeychain,
	}, nil
}

func init() {
	apiv1.Register(apiv1.MacKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// Close is a noop that just returns nil.
func (k *MacKMS) Close() error {
	return nil
}

// GetPublicKey returns the public key from the given URI in the request name.
func (k *MacKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("getPublicKeyRequest 'name' cannot be empty")
	}

	u, err := parseURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("mackms GetPublicKey failed: %w", err)
	}

	key, err := getPrivateKey(u)
	if err != nil {
		return nil, fmt.Errorf("mackms GetPublicKey failed: %w", apiv1Error(err))
	}
	defer key.Release()

	pub, _, err := extractPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("mackms GetPublicKey failed: %w", err)
	}

	return pub, nil
}

// CreateKey generates a new key on the Keychain or Secure Enclave using the
// Apple Security framework.
func (k *MacKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("createKeyRequest 'name' cannot be empty")
	}

	u, err := parseURI(req.Name)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
	}

	alg, ok := signatureAlgorithmMapping[req.SignatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("createKeyRequest 'signatureAlgorithm=%q' is not supported", req.SignatureAlgorithm)
	}
	if u.useSecureEnclave && req.SignatureAlgorithm != apiv1.UnspecifiedSignAlgorithm &&
		req.SignatureAlgorithm != apiv1.ECDSAWithSHA256 &&
		req.SignatureAlgorithm != apiv1.ECDSAWithSHA384 {
		return nil, fmt.Errorf("createKeyRequest 'signatureAlgorithm=%q' is not supported on Secure Enclave", req.SignatureAlgorithm)
	}

	u.sigAlgorithm = req.SignatureAlgorithm
	if alg.Type == "RSA" && req.Bits > 0 {
		u.keySize = req.Bits
	} else {
		u.keySize = alg.Size
	}

	// Define key attributes
	cfLabel, err := cf.NewString(u.label)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
	}
	defer cfLabel.Release()

	keyAttributesDict := cf.Dictionary{
		security.KSecAttrIsPermanent: cf.True,
	}
	if u.tag != "" {
		cfTag, err := cf.NewData([]byte(u.tag))
		if err != nil {
			return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
		}
		defer cfTag.Release()
		keyAttributesDict[security.KSecAttrApplicationTag] = cfTag
	}
	if u.useSecureEnclave {
		// After the first unlock, the data remains accessible until the next
		// restart. This is recommended for items that need to be accessed by
		// background applications. Items with this attribute do not migrate to
		// a new device. Thus, after restoring from a backup of a different
		// device, these items will not be present.
		//
		// TODO: make this a configuration option
		flags := security.KSecAccessControlPrivateKeyUsage
		if u.useBiometrics {
			flags |= security.KSecAccessControlAnd
			flags |= security.KSecAccessControlBiometryCurrentSet
		}
		access, err := security.SecAccessControlCreateWithFlags(
			security.KSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
			flags,
		)
		if err != nil {
			return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
		}
		defer access.Release()
		keyAttributesDict[security.KSecAttrAccessControl] = access
	}

	keyAttributes, err := cf.NewDictionary(keyAttributesDict)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
	}
	defer keyAttributes.Release()

	bits := cf.NewNumber(u.keySize)
	defer bits.Release()

	// Define key attributes
	attrsDict := cf.Dictionary{
		security.KSecAttrLabel:         cfLabel,
		security.KSecAttrKeySizeInBits: bits,
		security.KSecPrivateKeyAttrs:   keyAttributes,
	}
	if u.useSecureEnclave {
		attrsDict[security.KSecAttrTokenID] = security.KSecAttrTokenIDSecureEnclave
	} else {
		attrsDict[security.KSecPublicKeyAttrs] = keyAttributes
	}

	switch u.sigAlgorithm {
	case apiv1.UnspecifiedSignAlgorithm:
		attrsDict[security.KSecAttrKeyType] = security.KSecAttrKeyTypeECSECPrimeRandom
	case apiv1.ECDSAWithSHA256, apiv1.ECDSAWithSHA384, apiv1.ECDSAWithSHA512:
		attrsDict[security.KSecAttrKeyType] = security.KSecAttrKeyTypeECSECPrimeRandom
	case apiv1.SHA256WithRSA, apiv1.SHA384WithRSA, apiv1.SHA512WithRSA:
		attrsDict[security.KSecAttrKeyType] = security.KSecAttrKeyTypeRSA
	case apiv1.SHA256WithRSAPSS, apiv1.SHA384WithRSAPSS, apiv1.SHA512WithRSAPSS:
		attrsDict[security.KSecAttrKeyType] = security.KSecAttrKeyTypeRSA
	default:
		return nil, fmt.Errorf("mackms CreateKey failed: unsupported signature algorithm %s", u.sigAlgorithm)
	}

	attrs, err := cf.NewDictionary(attrsDict)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
	}
	defer attrs.Release()

	secKeyRef, err := security.SecKeyCreateRandomKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", apiv1Error(err))
	}
	defer secKeyRef.Release()

	pub, hash, err := extractPublicKey(secKeyRef)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
	}

	name := uri.New(Scheme, url.Values{
		"label": []string{u.label},
		"tag":   []string{u.tag},
		"hash":  []string{hex.EncodeToString(hash)},
	})
	if u.useSecureEnclave {
		name.Values.Set("se", "true")
	}
	if u.useBiometrics {
		name.Values.Set("bio", "true")
	}

	return &apiv1.CreateKeyResponse{
		Name:      name.String(),
		PublicKey: pub,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: name.String(),
		},
	}, nil
}

// CreateSigner returns a new [crypto.Signer] from the given URI in the request
// signing key.
func (k *MacKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, fmt.Errorf("createSignerRequest 'signingKey' cannot be empty")
	}

	u, err := parseURI(req.SigningKey)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateSigner failed: %w", err)
	}

	key, err := getPrivateKey(u)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateSigner failed: %w", apiv1Error(err))
	}
	defer key.Release()

	pub, _, err := extractPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateSigner failed: %w", err)
	}

	return &Signer{
		keyAttributes: u,
		pub:           pub,
	}, nil
}

// LoadCertificate returns an x509.Certificate by its label and/or serial
// number. By default Apple Keychain will use the certificate common name as the
// label.
//
// Valid names (URIs) are:
//   - mackms:label=test@example.com
//   - mackms:serial=2c273934eda8454d2595a94497e2395a
//   - mackms:label=test@example.com;serial=2c273934eda8454d2595a94497e2395a
//
// On code-signed applications, it is possible to use the Data Protection
// Keychain by default if [UseDataProtectionKeychain] is set to true. You can
// also select the keychain using the "keychain" attribute:
//   - "mackms:label=my-label;keychain=dataProtection"
//   - "mackms:label=my-label;keychain=login"
//
// Currently, only the keychains dataProtection and login are supported.
func (k *MacKMS) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("loadCertificateRequest 'name' cannot be empty")
	}

	// Require label or serial
	u, err := parseCertURI(req.Name, k.useDataProtectionKeychain, true)
	if err != nil {
		return nil, fmt.Errorf("mackms LoadCertificate failed: %w", err)
	}

	cert, err := loadCertificate(u, nil)
	if err != nil {
		return nil, fmt.Errorf("mackms LoadCertificate failed: %w", apiv1Error(err))
	}

	return cert, nil
}

// StoreCertificate stores a certificate in the Apple Keychain. There is no need
// to provide a label in the URI as Apple will use the CommonName as the default
// label, but if one is provided, the certificate in the Keychain will be
// updated with the given label:
//
// Valid names (URIs) are:
//   - "" will use the common name as the label
//   - "mackms:" will use the common name
//   - "mackms:label=my-label" will use "my-label"
//   - "mackms:my-label" will use the "my-label"
//
// On code-signed applications, it is possible to use the Data Protection
// Keychain by default if [UseDataProtectionKeychain] is set to true. You can
// also select the keychain using the "keychain" attribute:
//   - "mackms:label=my-label;keychain=dataProtection"
//   - "mackms:label=my-label;keychain=login"
//
// Currently, only the keychains dataProtection and login are supported.
func (k *MacKMS) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	// There's not really need to require the name as macOS will use the common
	// name as default.
	if req.Certificate == nil {
		return fmt.Errorf("storeCertificateRequest 'certificate' cannot be empty")
	}

	// Do not require any parameter. Using mackms: is allowed as macOS will set
	// the commonName as label.
	u, err := parseCertURI(req.Name, k.useDataProtectionKeychain, false)
	if err != nil {
		return fmt.Errorf("mackms StoreCertificate failed: %w", err)
	}

	// Write the certificate in the Data Protection Keychain if the key is in
	// the secure enclave.
	if u.keychain == "" && !u.useDataProtectionKeychain {
		if attrs, err := getKeyAttributes(req.Certificate.PublicKey); err == nil {
			defer attrs.Release()
			if security.GetSecAttrTokenID(attrs) == "com.apple.setoken" {
				u.useDataProtectionKeychain = true
			}
		}
	}

	// Store the certificate and update the label if required
	if err := storeCertificate(u, req.Certificate); err != nil {
		return fmt.Errorf("mackms StoreCertificate failed: %w", apiv1Error(err))
	}

	return nil
}

// LoadCertificateChain returns the leaf certificate by label and/or serial
// number and its intermediate certificates. By default Apple Keychain will use
// the certificate common name as the label.
//
// Valid names (URIs) are:
//   - mackms:label=test@example.com
//   - mackms:serial=2c273934eda8454d2595a94497e2395a
//   - mackms:label=test@example.com;serial=2c273934eda8454d2595a94497e2395a
func (k *MacKMS) LoadCertificateChain(req *apiv1.LoadCertificateChainRequest) ([]*x509.Certificate, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("loadCertificateChainRequest 'name' cannot be empty")
	}

	// Require label or serial
	u, err := parseCertURI(req.Name, k.useDataProtectionKeychain, true)
	if err != nil {
		return nil, fmt.Errorf("mackms LoadCertificateChain failed: %w", err)
	}

	cert, err := loadCertificate(u, nil)
	if err != nil {
		return nil, fmt.Errorf("mackms LoadCertificateChain failed: %w", apiv1Error(err))
	}

	chain := []*x509.Certificate{cert}
	if isSelfSigned(cert) {
		return chain, nil
	}

	// Look for the rest of intermediates skipping the root.
	chainURI := &certAttributes{useDataProtectionKeychain: u.useDataProtectionKeychain}
	for {
		// The Keychain stores the subject as an attribute, but it saves some of
		// the values in uppercase. We cannot use the cert.RawIssuer to restrict
		// more the search with KSecAttrSubjectKeyID and kSecAttrSubject. To do
		// it we will need to "normalize" the subject it in the same way.
		parent, err := loadCertificate(chainURI, cert.AuthorityKeyId)
		if err != nil || isSelfSigned(parent) || cert.CheckSignatureFrom(parent) != nil {
			break
		}
		cert = parent
		chain = append(chain, cert)
	}

	//nolint:nilerr // return only the intermediates present in keychain
	return chain, nil
}

// StoreCertificateChain stores a certificate chain in the Apple Keychain. There
// is no need to provide a label in the URI as Apple will use the CommonName as
// the default label, but if one is provided, the leaf certificate in the
// Keychain will be updated with the given label:
//
// Valid names (URIs) are:
//   - "" will use the common name as the label
//   - "mackms:" will use the common name
//   - "mackms:label=my-label" will use "my-label"
//   - "mackms:my-label" will use the "my-label"
func (k *MacKMS) StoreCertificateChain(req *apiv1.StoreCertificateChainRequest) error {
	// There's not really need to require the name as macOS will use the common
	// name as default.
	if len(req.CertificateChain) == 0 {
		return fmt.Errorf("storeCertificateChainRequest 'certificateChain' cannot be empty")
	}

	// Do not require any parameter. Using mackms: is allowed as macOS will set
	// the commonName as label.
	u, err := parseCertURI(req.Name, k.useDataProtectionKeychain, false)
	if err != nil {
		return fmt.Errorf("mackms StoreCertificateChain failed: %w", err)
	}

	// Write the certificate in the Data Protection Keychain if the key is in
	// the secure enclave.
	if u.keychain == "" && !u.useDataProtectionKeychain {
		if attrs, err := getKeyAttributes(req.CertificateChain[0].PublicKey); err == nil {
			defer attrs.Release()
			if security.GetSecAttrTokenID(attrs) == "com.apple.setoken" {
				u.useDataProtectionKeychain = true
			}
		}
	}

	// Store the certificate and update the label if required
	if err := storeCertificate(u, req.CertificateChain[0]); err != nil {
		return fmt.Errorf("mackms StoreCertificateChain failed: %w", apiv1Error(err))
	}

	// Store the rest of the chain but do not fail if already exists
	chainURI := &certAttributes{useDataProtectionKeychain: u.useDataProtectionKeychain}
	for _, cert := range req.CertificateChain[1:] {
		if err := storeCertificate(chainURI, cert); err != nil && !errors.Is(err, security.ErrAlreadyExists) {
			return fmt.Errorf("mackms StoreCertificateChain failed: %w", err)
		}
	}

	return nil
}

// DeleteKey deletes the key referenced by the URI in the request name.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (*MacKMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("deleteKeyRequest 'name' cannot be empty")
	}

	u, err := parseURI(req.Name)
	if err != nil {
		return fmt.Errorf("mackms DeleteKey failed: %w", err)
	}

	cfLabel, err := cf.NewString(u.label)
	if err != nil {
		return fmt.Errorf("mackms DeleteKey failed: %w", err)
	}
	defer cfLabel.Release()

	for _, keyClass := range []cf.TypeRef{security.KSecAttrKeyClassPublic, security.KSecAttrKeyClassPrivate} {
		dict := cf.Dictionary{
			security.KSecClass:        security.KSecClassKey,
			security.KSecAttrLabel:    cfLabel,
			security.KSecAttrKeyClass: keyClass,
		}
		if u.tag != "" {
			cfTag, err := cf.NewData([]byte(u.tag))
			if err != nil {
				return fmt.Errorf("mackms DeleteKey failed: %w", err)
			}
			defer cfTag.Release() //nolint:gocritic // only two iterations
			dict[security.KSecAttrApplicationTag] = cfTag
		}
		if u.useSecureEnclave {
			dict[security.KSecUseDataProtectionKeychain] = cf.True
		} else {
			dict[security.KSecUseDataProtectionKeychain] = cf.False
		}
		// Extract logic to deleteItem to avoid defer on loops
		if err := deleteItem(dict, u.hash); err != nil {
			return fmt.Errorf("mackms DeleteKey failed: %w", apiv1Error(err))
		}
	}

	return nil
}

// DeleteCertificate deletes the certificate referenced by the URI in the
// request name.
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (k *MacKMS) DeleteCertificate(req *apiv1.DeleteCertificateRequest) error {
	if req.Name == "" {
		return fmt.Errorf("deleteCertificateRequest 'name' cannot be empty")
	}

	u, err := parseCertURI(req.Name, k.useDataProtectionKeychain, true)
	if err != nil {
		return fmt.Errorf("mackms DeleteCertificate failed: %w", err)
	}

	query := cf.Dictionary{
		security.KSecClass:      security.KSecClassCertificate,
		security.KSecMatchLimit: security.KSecMatchLimitOne,
	}
	if u.label != "" {
		cfLabel, err := cf.NewString(u.label)
		if err != nil {
			return fmt.Errorf("mackms DeleteCertificate failed: %w", err)
		}
		defer cfLabel.Release()
		query[security.KSecAttrLabel] = cfLabel
	}
	if u.serialNumber != nil {
		cfSerial, err := cf.NewData(encodeSerialNumber(u.serialNumber))
		if err != nil {
			return fmt.Errorf("mackms DeleteCertificate failed: %w", err)
		}
		defer cfSerial.Release()
		query[security.KSecAttrSerialNumber] = cfSerial
	}
	if u.useDataProtectionKeychain {
		query[security.KSecUseDataProtectionKeychain] = cf.True
	} else {
		query[security.KSecUseDataProtectionKeychain] = cf.False
	}

	if err := deleteItem(query, nil); err != nil {
		return fmt.Errorf("mackms DeleteCertificate failed: %w", apiv1Error(err))
	}

	return nil
}

// SearchKeys searches for keys according to the query URI in the request. By default,
// all keys managed by the KMS using the default tag, and both Secure Enclave as well as
// non-Secure Enclave keys will be returned.
//
//   - "mackms:" will return all keys managed by the KMS  (using the default tag)
//   - "mackms:label=my-label" will return all keys using label "my-label" (and the default tag)
//   - "mackms:hash=the-hash" will return all keys having hash "hash" (and the default tag; generally one result)
//   - "mackms:tag=my-tag" will search for all keys with "my-tag"
//   - "mackms:se=true" will return all Secure Enclave keys managed by the KMS (using the default tag)
//   - "mackms:se=false" will return all non-Secure Enclave keys managed by the KMS (using the default tag)
//
// # Experimental
//
// Notice: This API is EXPERIMENTAL and may be changed or removed in a later
// release.
func (k *MacKMS) SearchKeys(req *apiv1.SearchKeysRequest) (*apiv1.SearchKeysResponse, error) {
	if req.Query == "" {
		return nil, fmt.Errorf("searchKeysRequest 'query' cannot be empty")
	}

	u, err := parseSearchURI(req.Query)
	if err != nil {
		return nil, fmt.Errorf("failed parsing query: %w", err)
	}

	keys, err := getPrivateKeys(u)
	if err != nil {
		return nil, fmt.Errorf("failed getting keys: %w", err)
	}

	results := make([]apiv1.SearchKeyResult, len(keys))
	for i, key := range keys {
		d := cf.NewDictionaryRef(cf.TypeRef(key.TypeRef()))
		var (
			hash    = security.GetSecAttrApplicationLabel(d)
			label   = security.GetSecAttrLabel(d)
			tag     = security.GetSecAttrApplicationTag(d)
			tokenID = security.GetSecAttrTokenID(d)
		)
		d.Release()

		name := uri.New(Scheme, url.Values{})
		name.Values.Set("hash", hex.EncodeToString(hash))
		name.Values.Set("label", label)
		name.Values.Set("tag", tag)

		keyInSecureEnclave := tokenID == "com.apple.setoken" //nolint:gosec // this is not a credential
		switch {
		case !u.secureEnclaveSet && keyInSecureEnclave:
			name.Values.Set("se", "true")
		case !u.secureEnclaveSet && !keyInSecureEnclave:
			name.Values.Set("se", "false")
		case u.useSecureEnclave && keyInSecureEnclave:
			name.Values.Set("se", "true")
		case !u.useSecureEnclave && !keyInSecureEnclave:
			name.Values.Set("se", "false")
		default:
			// skip in case the query doesn't match the actual property
			continue
		}

		// obtain the public key by requesting it, as the current
		// representation of the key includes just the attributes.
		pub, err := k.GetPublicKey(&apiv1.GetPublicKeyRequest{
			Name: name.String(),
		})
		if err != nil {
			return nil, fmt.Errorf("failed getting public key: %w", err)
		}

		results[i] = apiv1.SearchKeyResult{
			Name:      name.String(),
			PublicKey: pub,
			CreateSignerRequest: apiv1.CreateSignerRequest{
				SigningKey: name.String(),
			},
		}
	}

	return &apiv1.SearchKeysResponse{
		Results: results,
	}, nil
}

var _ apiv1.SearchableKeyManager = (*MacKMS)(nil)

func deleteItem(dict cf.Dictionary, hash []byte) error {
	if len(hash) > 0 {
		cfHash, err := cf.NewData(hash)
		if err != nil {
			return err
		}
		defer cfHash.Release()
		dict[security.KSecAttrApplicationLabel] = cfHash
	}

	query, err := cf.NewDictionary(dict)
	if err != nil {
		return err
	}
	defer query.Release()

	if err := security.SecItemDelete(query); err != nil {
		if dict[security.KSecAttrKeyClass] == security.KSecAttrKeyClassPublic && errors.Is(err, security.ErrNotFound) {
			return nil
		}
		return err
	}

	return nil
}

func getPrivateKey(u *keyAttributes) (*security.SecKeyRef, error) {
	dict := cf.Dictionary{
		security.KSecClass:        security.KSecClassKey,
		security.KSecAttrKeyClass: security.KSecAttrKeyClassPrivate,
		security.KSecReturnRef:    cf.True,
		security.KSecMatchLimit:   security.KSecMatchLimitOne,
	}
	if u.label != "" {
		cfLabel, err := cf.NewString(u.label)
		if err != nil {
			return nil, err
		}
		defer cfLabel.Release()
		dict[security.KSecAttrLabel] = cfLabel
	}
	if u.tag != "" {
		cfTag, err := cf.NewData([]byte(u.tag))
		if err != nil {
			return nil, err
		}
		defer cfTag.Release()
		dict[security.KSecAttrApplicationTag] = cfTag
	}
	if len(u.hash) > 0 {
		d, err := cf.NewData(u.hash)
		if err != nil {
			return nil, err
		}
		defer d.Release()
		dict[security.KSecAttrApplicationLabel] = d
	}
	if u.useSecureEnclave {
		dict[security.KSecUseDataProtectionKeychain] = cf.True
	} else {
		dict[security.KSecUseDataProtectionKeychain] = cf.False
	}

	// Get the query from the keychain
	query, err := cf.NewDictionary(dict)
	if err != nil {
		return nil, err
	}
	defer query.Release()

	var key cf.TypeRef
	if err := security.SecItemCopyMatching(query, &key); err != nil {
		// If not found retry without the tag if it wasn't set.
		if errors.Is(err, security.ErrNotFound) {
			if ru := u.retryAttributes(); ru != nil {
				return getPrivateKey(ru)
			}
		}
		return nil, fmt.Errorf("macOS SecItemCopyMatching failed: %w", err)
	}
	return security.NewSecKeyRef(key), nil
}

func getPrivateKeys(u *keySearchAttributes) ([]*security.SecKeychainItemRef, error) {
	dict := cf.Dictionary{
		security.KSecClass:            security.KSecClassKey,
		security.KSecAttrKeyClass:     security.KSecAttrKeyClassPrivate,
		security.KSecReturnAttributes: cf.True, // return keychain attributes, i.e. tag and label
		security.KSecMatchLimit:       security.KSecMatchLimitAll,
	}

	if u.tag != "" {
		cfTag, err := cf.NewData([]byte(u.tag))
		if err != nil {
			return nil, err
		}
		defer cfTag.Release()
		dict[security.KSecAttrApplicationTag] = cfTag
	}
	if u.label != "" {
		cfLabel, err := cf.NewString(u.label)
		if err != nil {
			return nil, err
		}
		defer cfLabel.Release()
		dict[security.KSecAttrLabel] = cfLabel
	}
	if len(u.hash) > 0 {
		cfHash, err := cf.NewData(u.hash)
		if err != nil {
			return nil, err
		}
		defer cfHash.Release()
		dict[security.KSecAttrApplicationLabel] = cfHash
	}

	// construct the query
	query, err := cf.NewDictionary(dict)
	if err != nil {
		return nil, err
	}
	defer query.Release()

	// perform the query
	var result cf.TypeRef
	err = security.SecItemCopyMatching(query, &result)
	if err != nil {
		if errors.Is(err, security.ErrNotFound) {
			return []*security.SecKeychainItemRef{}, nil
		}
		return nil, fmt.Errorf("macOS SecItemCopyMatching failed: %w", err)
	}

	array := cf.NewArrayRef(result)
	defer array.Release()

	keys := make([]*security.SecKeychainItemRef, array.Len())
	for i := 0; i < array.Len(); i++ {
		item := array.Get(i)
		key := security.NewSecKeychainItemRef(item)
		key.Retain() // retain the key, so that it's not released early
		keys[i] = key
	}

	return keys, nil
}

func getKeyAttributes(pub crypto.PublicKey) (*cf.DictionaryRef, error) {
	hash, err := createHash(pub)
	if err != nil {
		return nil, err
	}

	cfHash, err := cf.NewData(hash)
	if err != nil {
		return nil, err
	}
	defer cfHash.Release()

	query, err := cf.NewDictionary(cf.Dictionary{
		security.KSecClass:                security.KSecClassKey,
		security.KSecAttrKeyClass:         security.KSecAttrKeyClassPrivate,
		security.KSecReturnRef:            cf.True,
		security.KSecMatchLimit:           security.KSecMatchLimitOne,
		security.KSecAttrApplicationLabel: cfHash,
	})
	if err != nil {
		return nil, err
	}
	defer query.Release()

	var ref cf.TypeRef
	err = security.SecItemCopyMatching(query, &ref)
	if err != nil {
		return nil, err
	}
	defer ref.Release()

	return security.SecKeyCopyAttributes(security.NewSecKeyRef(ref)), nil
}

func extractPublicKey(secKeyRef *security.SecKeyRef) (crypto.PublicKey, []byte, error) {
	// Get the hash of the public key. We can also calculate this from the
	// external representation below, but in case Apple decides to switch from
	// SHA-1, let's just use what macOS sets by default.
	attrs := security.SecKeyCopyAttributes(secKeyRef)
	defer attrs.Release()
	hash := security.GetSecAttrApplicationLabel(attrs)

	// Attempt to extract the public key, it will fail if the app that created
	// the private key didn’t also store the corresponding public key in the
	// keychain, or if the system can’t reconstruct the corresponding public
	// key.
	if publicKey, err := security.SecKeyCopyPublicKey(secKeyRef); err == nil {
		defer publicKey.Release()

		// For an unknown reason this sometimes fails with the error -25293
		// (errSecAuthFailed). If this happens attempt to extract the key from
		// the private key.
		if data, err := security.SecKeyCopyExternalRepresentation(publicKey); err == nil {
			defer data.Release()

			derBytes := data.Bytes()
			// ECDSA public keys are formatted as "04 || X || Y"
			if derBytes[0] == 0x04 {
				pub, err := parseECDSAPublicKey(derBytes)
				if err != nil {
					return nil, nil, fmt.Errorf("error parsing ECDSA key: %w", err)
				}
				return pub, hash, nil
			}

			// RSA public keys are formatted using PKCS #1
			pub, err := x509.ParsePKCS1PublicKey(derBytes)
			if err != nil {
				return nil, nil, fmt.Errorf("error parsing RSA key: %w", err)
			}

			return pub, hash, nil
		}
	}

	// At this point we only have the private key.
	data, err := security.SecKeyCopyExternalRepresentation(secKeyRef)
	if err != nil {
		return nil, nil, fmt.Errorf("macOS SecKeyCopyExternalRepresentation failed: %w", err)
	}
	defer data.Release()

	derBytes := data.Bytes()

	// ECDSA private keys are formatted as "04 || X || Y || K"
	if derBytes[0] == 0x04 {
		pub, err := parseECDSAPrivateKey(derBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("error parsing ECDSA key: %w", err)
		}
		return pub, hash, nil
	}

	// RSA private keys are formatted using PKCS #1
	priv, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing key: %w", err)
	}
	return priv.Public(), hash, nil
}

// isSelfSigned checks if a certificate is self signed. The algorithm looks like this:
//
//	If subject != issuer: false
//	ElseIf subjectKeyID != authorityKey: false
//	ElseIf checkSignature: true
//	Otherwise: false
func isSelfSigned(cert *x509.Certificate) bool {
	if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		if cert.SubjectKeyId != nil && cert.AuthorityKeyId != nil && !bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId) {
			return false
		}

		return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
	}

	return false
}

func loadCertificate(u *certAttributes, subjectKeyID []byte) (*x509.Certificate, error) {
	query := cf.Dictionary{
		security.KSecClass:      security.KSecClassCertificate,
		security.KSecMatchLimit: security.KSecMatchLimitOne,
		security.KSecReturnRef:  cf.True,
	}
	if u.label != "" {
		cfLabel, err := cf.NewString(u.label)
		if err != nil {
			return nil, err
		}
		defer cfLabel.Release()
		query[security.KSecAttrLabel] = cfLabel
	}
	if u.serialNumber != nil {
		cfSerial, err := cf.NewData(encodeSerialNumber(u.serialNumber))
		if err != nil {
			return nil, err
		}
		defer cfSerial.Release()
		query[security.KSecAttrSerialNumber] = cfSerial
	}
	if subjectKeyID != nil {
		cfSubjectKeyID, err := cf.NewData(subjectKeyID)
		if err != nil {
			return nil, err
		}
		defer cfSubjectKeyID.Release()
		query[security.KSecAttrSubjectKeyID] = cfSubjectKeyID
	}
	// Apple recommends to set this parameters always to true for all keychain
	// operations. This requires a code-signed application.
	if u.useDataProtectionKeychain {
		query[security.KSecUseDataProtectionKeychain] = cf.True
	} else {
		query[security.KSecUseDataProtectionKeychain] = cf.False
	}

	cfQuery, err := cf.NewDictionary(query)
	if err != nil {
		return nil, err
	}
	defer cfQuery.Release()

	var ref cf.TypeRef
	if err := security.SecItemCopyMatching(cfQuery, &ref); err != nil {
		return nil, err
	}
	defer ref.Release()

	data, err := security.SecCertificateCopyData(security.NewSecCertificateRef(ref))
	if err != nil {
		return nil, err
	}
	defer data.Release()

	cert, err := x509.ParseCertificate(data.Bytes())
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func storeCertificate(u *certAttributes, cert *x509.Certificate) error {
	cfData, err := cf.NewData(cert.Raw)
	if err != nil {
		return err
	}
	defer cfData.Release()

	certRef, err := security.SecCertificateCreateWithData(cfData)
	if err != nil {
		return err
	}
	defer certRef.Release()

	// Adding the label here doesn't have any effect. Apple Keychain always uses
	// the commonName.
	dict := cf.Dictionary{
		security.KSecClass:    security.KSecClassCertificate,
		security.KSecValueRef: certRef,
	}
	// Apple recommends to set KSecUseDataProtectionKeychain parameters always
	// to true for all keychain operations. This option requires to use a
	// code-signed application.
	if u.useDataProtectionKeychain {
		dict[security.KSecUseDataProtectionKeychain] = cf.True
		// The data in the keychain item cannot be accessed after a restart
		// until the device has been unlocked once by the user.
		access, err := security.SecAccessControlCreateWithFlags(
			security.KSecAttrAccessibleAfterFirstUnlock,
			0,
		)
		if err != nil {
			return err
		}
		defer access.Release()
		dict[security.KSecAttrAccessControl] = access
	}

	attributes, err := cf.NewDictionary(dict)
	if err != nil {
		return err
	}
	defer attributes.Release()

	// Store the certificate
	if err := security.SecItemAdd(attributes, nil); err != nil {
		return err
	}

	// Update the label if necessary
	if u.label != "" && u.label != cert.Subject.CommonName {
		cfLabel, err := cf.NewString(u.label)
		if err != nil {
			return err
		}
		defer cfLabel.Release()

		query, err := cf.NewDictionary(cf.Dictionary{
			security.KSecValueRef: certRef,
		})
		if err != nil {
			return err
		}
		defer query.Release()

		update, err := cf.NewDictionary(cf.Dictionary{
			security.KSecAttrLabel: cfLabel,
		})
		if err != nil {
			return err
		}
		defer update.Release()

		if err := security.SecItemUpdate(query, update); err != nil {
			return err
		}
	}

	return nil
}

func parseURI(rawuri string) (*keyAttributes, error) {
	// When rawuri is just the key name
	if !strings.HasPrefix(strings.ToLower(rawuri), Scheme) {
		return &keyAttributes{
			label: rawuri,
			tag:   DefaultTag,
			retry: true,
		}, nil
	}

	// When rawuri is a mackms uri.
	u, err := uri.ParseWithScheme(Scheme, rawuri)
	if err != nil {
		return nil, err
	}

	// Special case for mackms:label
	if len(u.Values) == 1 {
		for k, v := range u.Values {
			if (len(v) == 1 && v[0] == "") || len(v) == 0 {
				return &keyAttributes{
					label: k,
					tag:   DefaultTag,
					retry: true,
				}, nil
			}
		}
	}

	// With regular values, uris look like this:
	// mackms:label=my-key;tag=my-tag;hash=010a...;se=true;bio=true
	label := u.Get("label")
	if label == "" {
		return nil, fmt.Errorf("error parsing %q: label is required", rawuri)
	}
	tag := u.Get("tag")
	if tag == "" && !u.Has("tag") {
		tag = DefaultTag
	}
	return &keyAttributes{
		label:            label,
		tag:              tag,
		hash:             u.GetEncoded("hash"),
		retry:            !u.Has("tag"),
		useSecureEnclave: u.GetBool("se"),
		useBiometrics:    u.GetBool("bio"),
	}, nil
}

func parseCertURI(rawuri string, useDataProtectionKeychain, requireValue bool) (*certAttributes, error) {
	// When rawuri is just the label
	if !strings.HasPrefix(strings.ToLower(rawuri), Scheme) {
		return &certAttributes{
			label: rawuri,
		}, nil
	}

	// When rawuri is a mackms uri.
	u, err := uri.ParseWithScheme(Scheme, rawuri)
	if err != nil {
		return nil, err
	}

	// Special case for mackms:label
	if len(u.Values) == 1 {
		for k, v := range u.Values {
			if (len(v) == 1 && v[0] == "") || len(v) == 0 {
				return &certAttributes{
					label: k,
				}, nil
			}
		}
	}

	// With regular values, uris look like this:
	// mackms:label=my-cert;serial=01020A0B...
	label := u.Get("label")
	keychain := u.Get("keychain")
	serial := u.GetEncoded("serial")
	if requireValue && label == "" && len(serial) == 0 {
		return nil, fmt.Errorf("error parsing %q: label or serial are required", rawuri)
	}

	var serialNumber *big.Int
	if len(serial) > 0 {
		serialNumber = new(big.Int).SetBytes(serial)
	}

	return &certAttributes{
		label:                     label,
		serialNumber:              serialNumber,
		useDataProtectionKeychain: isDataProtectionKeychain(keychain, useDataProtectionKeychain),
		keychain:                  keychain,
	}, nil
}

func parseSearchURI(rawuri string) (*keySearchAttributes, error) {
	// When rawuri is just the key name
	if !strings.HasPrefix(strings.ToLower(rawuri), Scheme) {
		return &keySearchAttributes{
			label: rawuri,
			tag:   DefaultTag,
		}, nil
	}

	// When rawuri is a mackms uri.
	u, err := uri.Parse(rawuri)
	if err != nil {
		return nil, err
	}

	// Special case for mackms:label
	if len(u.Values) == 1 {
		for k, v := range u.Values {
			if (len(v) == 1 && v[0] == "") || len(v) == 0 {
				return &keySearchAttributes{
					label: k,
					tag:   DefaultTag,
				}, nil
			}
		}
	}

	// With regular values, uris look like this:
	// mackms:label=my-key;tag=my-tag;hash=010a...;se=true;bio=true
	label := u.Get("label") // when searching, the label can be empty
	tag := u.Get("tag")
	if tag == "" && !u.Has("tag") {
		tag = DefaultTag
	}
	return &keySearchAttributes{
		label:            label,
		tag:              tag,
		hash:             u.GetEncoded("hash"),
		secureEnclaveSet: u.Values.Has("se"),
		useSecureEnclave: u.GetBool("se"),
	}, nil
}

func isDataProtectionKeychain(s string, defaultValue bool) bool {
	switch strings.ToLower(s) {
	case "dataprotection":
		return true
	case "login":
		return false
	case "":
		return defaultValue
	default:
		return false
	}
}

// encodeSerialNumber encodes the serial number of a certificate in ASN.1.
// Negative serial numbers are not allowed.
func encodeSerialNumber(s *big.Int) []byte {
	if s.Sign() == 0 {
		return []byte{0x00}
	}
	b := s.Bytes()
	if b[0]&0x80 != 0 {
		// Pad this with 0x00 in order to stop it looking like a negative number.
		return append([]byte{0x00}, b...)
	}
	return b
}

func parseECDSAPublicKey(raw []byte) (crypto.PublicKey, error) {
	switch len(raw) / 2 {
	case 32: // 65 bytes
		key, err := ecdh.P256().NewPublicKey(raw)
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key)
	case 48: // 97 bytes
		key, err := ecdh.P384().NewPublicKey(raw)
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key)
	case 66: // 133 bytes:
		key, err := ecdh.P521().NewPublicKey(raw)
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key)
	default:
		return nil, fmt.Errorf("unsupported ECDSA key with %d bytes", len(raw))
	}
}

func parseECDSAPrivateKey(raw []byte) (crypto.PublicKey, error) {
	switch len(raw) / 3 {
	case 32: // 97 bytes
		key, err := ecdh.P256().NewPrivateKey(raw[65:])
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key.PublicKey())
	case 48: // 145 bytes
		key, err := ecdh.P384().NewPrivateKey(raw[97:])
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key.PublicKey())
	case 66: // 199 bytes:
		key, err := ecdh.P521().NewPrivateKey(raw[133:])
		if err != nil {
			return nil, err
		}
		return ecdhToECDSAPublicKey(key.PublicKey())
	default:
		return nil, fmt.Errorf("unsupported ECDSA key with %d bytes", len(raw))
	}
}

func ecdhToECDSAPublicKey(key *ecdh.PublicKey) (*ecdsa.PublicKey, error) {
	rawKey := key.Bytes()
	switch key.Curve() {
	case ecdh.P256():
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0).SetBytes(rawKey[1:33]),
			Y:     big.NewInt(0).SetBytes(rawKey[33:]),
		}, nil
	case ecdh.P384():
		return &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     big.NewInt(0).SetBytes(rawKey[1:49]),
			Y:     big.NewInt(0).SetBytes(rawKey[49:]),
		}, nil
	case ecdh.P521():
		return &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     big.NewInt(0).SetBytes(rawKey[1:67]),
			Y:     big.NewInt(0).SetBytes(rawKey[67:]),
		}, nil
	default:
		return nil, errors.New("failed to convert *ecdh.PublicKey to *ecdsa.PublicKey")
	}
}

// createHash creates the SHA-1 of the DER representation of an RSA public key
// using the PKCS #1 format or the SHA-1 of the uncompressed ECDSA point
// according to SEC 1, Version 2.0, Section 2.3.4. It corresponds to the
// kSecAttrApplicationLabel attribute
func createHash(key crypto.PublicKey) ([]byte, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		pub, err := k.ECDH()
		if err != nil {
			return nil, err
		}
		return sha1Sum(pub.Bytes()), nil
	case *rsa.PublicKey:
		return sha1Sum(x509.MarshalPKCS1PublicKey(k)), nil
	default:
		return nil, fmt.Errorf("usupported public key type %T", key)
	}
}

//nolint:gosec // required to calculate hash
func sha1Sum(b []byte) []byte {
	h := sha1.New()
	h.Write(b)
	return h.Sum(nil)
}

func apiv1Error(err error) error {
	switch {
	case errors.Is(err, security.ErrNotFound):
		return apiv1.NotFoundError{
			Message: err.Error(),
		}
	case errors.Is(err, security.ErrAlreadyExists):
		return apiv1.AlreadyExistsError{
			Message: err.Error(),
		}
	default:
		return err
	}
}
