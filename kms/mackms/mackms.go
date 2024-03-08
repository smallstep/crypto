//go:build darwin && cgo

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
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	useSecureEnclave bool
	useBiometrics    bool
	sigAlgorithm     apiv1.SignatureAlgorithm
	keySize          int
}

type keyType int8

const (
	ecdsaKeyType keyType = iota
	rsaKeyType
)

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

// MacKMS is a key manager that uses keys stored in the secure enclave.
type MacKMS struct{}

// New returns a new SoftKMS.
func New(context.Context, apiv1.Options) (*MacKMS, error) {
	return &MacKMS{}, nil
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
		return nil, fmt.Errorf("mackms GetPublicKey failed: %w", err)
	}
	defer key.Release()

	pub, _, err := extractPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("mackms GetPublicKey failed: %w", err)
	}

	return pub, nil
}

// CreateKey generates a new key on the Keychain or Secure Enclave using Apple
// Security framework.
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
	if u.useSecureEnclave && req.SignatureAlgorithm != apiv1.UnspecifiedSignAlgorithm && req.SignatureAlgorithm != apiv1.ECDSAWithSHA256 {
		return nil, fmt.Errorf("createKeyRequest 'signatureAlgorithm=%q' is not supported on Secure Enclave", req.SignatureAlgorithm)
	}

	u.sigAlgorithm = req.SignatureAlgorithm
	if alg.Type == "RSA" && req.Bits > 0 {
		u.keySize = req.Bits
	} else {
		u.keySize = alg.Size
	}

	// Define key attributes
	cfTag, err := cf.NewData([]byte(u.tag))
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
	}
	defer cfTag.Release()

	cfLabel, err := cf.NewString(u.label)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
	}
	defer cfLabel.Release()

	keyAttributesDict := cf.Dictionary{
		security.KSecAttrApplicationTag: cfTag,
		security.KSecAttrIsPermanent:    cf.True,
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
			security.KSecAttrAccessibleWhenUnlockedThisDeviceOnly,
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
		return nil, err
	}
	defer attrs.Release()

	secKeyRef, err := security.SecKeyCreateRandomKey(attrs)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
	}
	defer secKeyRef.Release()

	pub, hash, err := extractPublicKey(secKeyRef)
	if err != nil {
		return nil, fmt.Errorf("mackms CreateKey failed: %w", err)
	}

	// TODO(mariano) calculate hash
	name := uri.New(Scheme, url.Values{
		"label": []string{u.label},
		"tag":   []string{u.tag},
		"hash":  []string{hex.EncodeToString(hash)},
	})
	fmt.Printf("%#v\n", u)
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
		return nil, err
	}

	key, err := getPrivateKey(u)
	if err != nil {
		return nil, err
	}
	defer key.Release()

	pub, _, err := extractPublicKey(key)
	if err != nil {
		return nil, err
	}

	return &Signer{
		keyAttributes: u,
		pub:           pub,
	}, nil
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

	cfTag, err := cf.NewData([]byte(u.tag))
	if err != nil {
		return fmt.Errorf("mackms DeleteKey failed: %w", err)
	}
	defer cfTag.Release()

	cfLabel, err := cf.NewString(u.label)
	if err != nil {
		return fmt.Errorf("mackms DeleteKey failed: %w", err)
	}
	defer cfLabel.Release()

	for _, keyClass := range []cf.TypeRef{security.KSecAttrKeyClassPublic, security.KSecAttrKeyClassPrivate} {
		queryDict := cf.Dictionary{
			security.KSecClass:              security.KSecClassKey,
			security.KSecAttrApplicationTag: cfTag,
			security.KSecAttrLabel:          cfLabel,
			security.KSecAttrKeyClass:       keyClass,
		}

		if len(u.hash) > 0 {
			d, err := cf.NewData(u.hash)
			if err != nil {
				return err
			}
			defer d.Release()
			queryDict[security.KSecAttrApplicationLabel] = d
		}

		query, err := cf.NewDictionary(queryDict)
		if err != nil {
			return fmt.Errorf("mackms DeleteKey failed: %w", err)
		}
		defer query.Release()

		if err := security.SecItemDelete(query); err != nil {
			if keyClass == security.KSecAttrKeyClassPublic && errors.Is(err, security.ErrNotFound) {
				continue
			}
			return fmt.Errorf("mackms DeleteKey failed: %w", err)
		}
	}

	return nil
}

func getPrivateKey(u *keyAttributes) (*security.SecKeyRef, error) {
	cfTag, err := cf.NewData([]byte(u.tag))
	if err != nil {
		return nil, err
	}
	defer cfTag.Release()

	cfLabel, err := cf.NewString(u.label)
	if err != nil {
		return nil, err
	}
	defer cfLabel.Release()

	queryDict := cf.Dictionary{
		security.KSecClass:              security.KSecClassKey,
		security.KSecAttrApplicationTag: cfTag,
		security.KSecAttrLabel:          cfLabel,
		security.KSecAttrKeyClass:       security.KSecAttrKeyClassPrivate,
		security.KSecReturnRef:          cf.True,
		security.KSecMatchLimit:         security.KSecMatchLimitOne,
	}
	if len(u.hash) > 0 {
		d, err := cf.NewData(u.hash)
		if err != nil {
			return nil, err
		}
		defer d.Release()
		queryDict[cf.TypeRef(security.KSecAttrApplicationLabel)] = d
	}

	// Get the query from the keychain
	query, err := cf.NewDictionary(queryDict)
	if err != nil {
		return nil, err
	}
	defer query.Release()

	var key cf.TypeRef
	if err := security.SecItemCopyMatching(query, &key); err != nil {
		return nil, fmt.Errorf("macOS SecItemCopyMatching failed: %w", err)
	}
	return security.NewSecKeyRef(key), nil
}

func extractPublicKey(secKeyRef *security.SecKeyRef) (crypto.PublicKey, []byte, error) {
	// Get the hash of the public key. We can also calculate this from the
	// external representation bellow, but in case Apple decides to switch from
	// SHA-1, let's just use what macOS sets by default.
	attrs := security.SecKeyCopyAttributes(secKeyRef)
	defer attrs.Release()
	hash := security.GetSecAttrApplicationLabel(attrs)

	// Attempt to extract the public key, it will fail if the app that created
	// the private key didn’t also store the corresponding public key in the
	// keychain, or if the system can’t reconstruct the corresponding public
	// key. If the public kay is not present it fails for ECDSA keys but not
	// for RSA keys 🤷‍♂️.
	if publicKey, err := security.SecKeyCopyPublicKey(secKeyRef); err == nil {
		defer publicKey.Release()

		data, err := security.SecKeyCopyExternalRepresentation(publicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("macOS SecKeyCopyExternalRepresentation failed: %w", err)
		}
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

	// At this point we only have the privatekey.
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

func parseURI(rawuri string) (*keyAttributes, error) {
	s := strings.ToLower(rawuri)

	// When rawuri is just the key name
	if !strings.HasPrefix(s, Scheme) {
		return &keyAttributes{
			label: rawuri,
			tag:   DefaultTag,
		}, nil
	}

	// When rawuri is a mackms uri.
	u, err := uri.ParseWithScheme(Scheme, s)
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
				}, nil
			}
		}
	}

	// With regular values, uris look like this:
	// mackms:label=my-key;tag=my-tag;hash=010a...;se=true;bio=true
	label := u.Get("label")
	if label == "" {
		return nil, fmt.Errorf("error parsing %s: label is required", rawuri)
	}
	tag := u.Get("tag")
	if tag == "" {
		tag = DefaultTag
	}
	return &keyAttributes{
		label:            label,
		tag:              tag,
		hash:             u.GetEncoded("hash"),
		useSecureEnclave: u.GetBool("se"),
		useBiometrics:    u.GetBool("bio"),
	}, nil
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
