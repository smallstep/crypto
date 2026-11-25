//go:build !noscwkms

package scwkms

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	km "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/uri"
	"go.step.sm/crypto/pemutil"
)

// Scheme is the scheme used in URIs, the string "scwkms".
const Scheme = string(apiv1.ScalewayKMS)

// signatureAlgorithmMapping maps apiv1.SignatureAlgorithm (and optional RSA Bits)
// to the Scaleway KeyAlgorithmAsymmetricSigning constant.
// Scaleway only supports SHA-256 for all algorithms, P-256 and P-384 for EC.
// Unsupported: SHA384WithRSA, SHA512WithRSA, SHA384WithRSAPSS, SHA512WithRSAPSS,
// ECDSAWithSHA512, and PureEd25519.
var signatureAlgorithmMapping = map[apiv1.SignatureAlgorithm]interface{}{
	apiv1.ECDSAWithSHA256: km.KeyAlgorithmAsymmetricSigningEcP256Sha256,
	apiv1.ECDSAWithSHA384: km.KeyAlgorithmAsymmetricSigningEcP384Sha384,
	apiv1.SHA256WithRSA: map[int]km.KeyAlgorithmAsymmetricSigning{
		0:    km.KeyAlgorithmAsymmetricSigningRsaPkcs1_3072Sha256,
		2048: km.KeyAlgorithmAsymmetricSigningRsaPkcs1_2048Sha256,
		3072: km.KeyAlgorithmAsymmetricSigningRsaPkcs1_3072Sha256,
		4096: km.KeyAlgorithmAsymmetricSigningRsaPkcs1_4096Sha256,
	},
	apiv1.SHA256WithRSAPSS: map[int]km.KeyAlgorithmAsymmetricSigning{
		0:    km.KeyAlgorithmAsymmetricSigningRsaPss3072Sha256,
		2048: km.KeyAlgorithmAsymmetricSigningRsaPss2048Sha256,
		3072: km.KeyAlgorithmAsymmetricSigningRsaPss3072Sha256,
		4096: km.KeyAlgorithmAsymmetricSigningRsaPss4096Sha256,
	},
}

// KeyManagementClient defines the subset of the Scaleway Key Manager API used by
// this package. The narrow interface enables unit testing with a mock.
type KeyManagementClient interface {
	CreateKey(req *km.CreateKeyRequest, opts ...scw.RequestOption) (*km.Key, error)
	GetKey(req *km.GetKeyRequest, opts ...scw.RequestOption) (*km.Key, error)
	GetPublicKey(req *km.GetPublicKeyRequest, opts ...scw.RequestOption) (*km.PublicKey, error)
	Sign(req *km.SignRequest, opts ...scw.RequestOption) (*km.SignResponse, error)
	Decrypt(req *km.DecryptRequest, opts ...scw.RequestOption) (*km.DecryptResponse, error)
	DeleteKey(req *km.DeleteKeyRequest, opts ...scw.RequestOption) error
}

// newKeyManagerClientFunc is the constructor for the Scaleway Key Manager API.
// It is a variable so it can be overridden in tests.
var newKeyManagerClientFunc = func(client *scw.Client) KeyManagementClient {
	return km.NewAPI(client)
}

// ScalewayKMS implements a KMS using Scaleway Key Manager.
type ScalewayKMS struct {
	client    KeyManagementClient
	region    scw.Region
	projectID string
}

// New creates a new ScalewayKMS. It reads configuration from the given
// apiv1.Options and from the Scaleway configuration file / environment variables.
//
// The URI format is:
//
//	scwkms:[key-id=<uuid>;region=<region>][?access-key=...&secret-key=...&project-id=...&organization-id=...&region=...&profile=...]
func New(_ context.Context, opts apiv1.Options) (*ScalewayKMS, error) {
	var (
		accessKey      string
		secretKey      string
		projectID      string
		organizationID string
		region         scw.Region
		profileName    string
	)

	if opts.URI != "" {
		u, err := uri.ParseWithScheme(Scheme, opts.URI)
		if err != nil {
			return nil, err
		}
		accessKey = u.Get("access-key")
		secretKey = u.Get("secret-key")
		projectID = u.Get("project-id")
		organizationID = u.Get("organization-id")
		region = scw.Region(u.Get("region"))
		profileName = u.Get("profile")
	}

	// opts.Region is a shared field — use it as fallback.
	if region == "" && opts.Region != "" {
		region = scw.Region(opts.Region)
	}

	var clientOpts []scw.ClientOption

	// Load Scaleway configuration file (~/.config/scw/config.yaml).
	cfg, cfgErr := scw.LoadConfig()
	if cfgErr == nil && cfg != nil {
		if profileName != "" {
			profile, err := cfg.GetProfile(profileName)
			if err != nil {
				return nil, fmt.Errorf("scwkms: error loading profile %q: %w", profileName, err)
			}
			clientOpts = append(clientOpts, scw.WithProfile(profile))
		} else if profile, err := cfg.GetActiveProfile(); err == nil {
			clientOpts = append(clientOpts, scw.WithProfile(profile))
		}
	}

	// Environment variables (SCW_ACCESS_KEY, SCW_SECRET_KEY, etc.) override the profile.
	clientOpts = append(clientOpts, scw.WithEnv())

	// Explicit URI parameters override everything else.
	if accessKey != "" && secretKey != "" {
		clientOpts = append(clientOpts, scw.WithAuth(accessKey, secretKey))
	}
	if projectID != "" {
		clientOpts = append(clientOpts, scw.WithDefaultProjectID(projectID))
	}
	if organizationID != "" {
		clientOpts = append(clientOpts, scw.WithDefaultOrganizationID(organizationID))
	}
	if region != "" {
		clientOpts = append(clientOpts, scw.WithDefaultRegion(region))
	}

	scwClient, err := scw.NewClient(clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("scwkms: error creating Scaleway client: %w", err)
	}

	// Determine effective region for use in key operation requests.
	if region == "" {
		if r, ok := scwClient.GetDefaultRegion(); ok {
			region = r
		}
	}
	// Determine effective project ID for key creation.
	if projectID == "" {
		if p, ok := scwClient.GetDefaultProjectID(); ok {
			projectID = p
		}
	}

	return &ScalewayKMS{
		client:    newKeyManagerClientFunc(scwClient),
		region:    region,
		projectID: projectID,
	}, nil
}

func init() {
	apiv1.Register(apiv1.ScalewayKMS, func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return New(ctx, opts)
	})
}

// NewScalewayKMS creates a ScalewayKMS with the given client. Intended for testing.
func NewScalewayKMS(client KeyManagementClient) *ScalewayKMS {
	return &ScalewayKMS{
		client: client,
	}
}

// Close is a no-op: the Scaleway client has no persistent connection to close.
func (k *ScalewayKMS) Close() error {
	return nil
}

// CreateSigner returns a new crypto.Signer backed by a Scaleway asymmetric
// signing key.
func (k *ScalewayKMS) CreateSigner(req *apiv1.CreateSignerRequest) (crypto.Signer, error) {
	if req.SigningKey == "" {
		return nil, fmt.Errorf("scwkms CreateSigner: 'signingKey' cannot be empty")
	}
	return NewSigner(k.client, req.SigningKey)
}

// CreateKey creates a new asymmetric key in Scaleway Key Manager.
// The key name in CreateKeyRequest is used as the Scaleway key name.
// The returned CreateKeyResponse.Name is a scwkms URI.
func (k *ScalewayKMS) CreateKey(req *apiv1.CreateKeyRequest) (*apiv1.CreateKeyResponse, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("scwkms CreateKey: 'name' cannot be empty")
	}

	usage, err := k.keyUsageFromRequest(req)
	if err != nil {
		return nil, err
	}

	name, _ := parseKeyName(req.Name, k.region)
	creq := &km.CreateKeyRequest{
		Region:      k.region,
		ProjectID:   k.projectID,
		Name:        &name,
		Usage:       usage,
		Unprotected: true, // allow DeleteKey; can be overridden by users after creation
	}

	key, err := k.client.CreateKey(creq)
	if err != nil {
		return nil, fmt.Errorf("scwkms CreateKey failed: %w", err)
	}

	// Build a scwkms URI from the returned key ID and region.
	keyURI := keyIDToURI(key.ID, key.Region)

	// Retrieve the public key to include in the response.
	pk, err := k.GetPublicKey(&apiv1.GetPublicKeyRequest{Name: keyURI})
	if err != nil {
		return nil, fmt.Errorf("scwkms GetPublicKey after CreateKey failed: %w", err)
	}

	return &apiv1.CreateKeyResponse{
		Name:      keyURI,
		PublicKey: pk,
		CreateSignerRequest: apiv1.CreateSignerRequest{
			SigningKey: keyURI,
		},
	}, nil
}

// keyUsageFromRequest maps the apiv1.CreateKeyRequest to a Scaleway KeyUsage.
func (k *ScalewayKMS) keyUsageFromRequest(req *apiv1.CreateKeyRequest) (*km.KeyUsage, error) {
	if req.SignatureAlgorithm == apiv1.UnspecifiedSignAlgorithm {
		// Default: EC P-256 SHA-256
		algo := km.KeyAlgorithmAsymmetricSigningEcP256Sha256
		return &km.KeyUsage{AsymmetricSigning: &algo}, nil
	}

	v, ok := signatureAlgorithmMapping[req.SignatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("scwkms does not support signature algorithm '%s'", req.SignatureAlgorithm)
	}

	switch v := v.(type) {
	case km.KeyAlgorithmAsymmetricSigning:
		algo := v
		return &km.KeyUsage{AsymmetricSigning: &algo}, nil
	case map[int]km.KeyAlgorithmAsymmetricSigning:
		algo, ok := v[req.Bits]
		if !ok {
			return nil, fmt.Errorf("scwkms does not support signature algorithm '%s' with %d bits", req.SignatureAlgorithm, req.Bits)
		}
		return &km.KeyUsage{AsymmetricSigning: &algo}, nil
	default:
		return nil, fmt.Errorf("scwkms: unexpected algorithm mapping type")
	}
}

// GetPublicKey retrieves the public key of the given Scaleway key.
// The name can be a bare UUID, or a scwkms URI (scwkms:key-id=...;region=...).
func (k *ScalewayKMS) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("scwkms GetPublicKey: 'name' cannot be empty")
	}

	keyID, region := parseKeyName(req.Name, k.region)

	response, err := k.client.GetPublicKey(&km.GetPublicKeyRequest{
		Region: region,
		KeyID:  keyID,
	})
	if err != nil {
		return nil, fmt.Errorf("scwkms GetPublicKey failed: %w", err)
	}

	pk, err := parsePublicKeyPEM([]byte(response.Pem))
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// DeleteKey deletes a key from Scaleway Key Manager.
//
// Note: keys created with Unprotected:true (the default in this package) can
// be deleted. Keys with Protected:true or in the Locked state will return an
// error from Scaleway.
func (k *ScalewayKMS) DeleteKey(req *apiv1.DeleteKeyRequest) error {
	if req.Name == "" {
		return fmt.Errorf("scwkms DeleteKey: 'name' cannot be empty")
	}

	keyID, region := parseKeyName(req.Name, k.region)

	if err := k.client.DeleteKey(&km.DeleteKeyRequest{
		Region: region,
		KeyID:  keyID,
	}); err != nil {
		return fmt.Errorf("scwkms DeleteKey failed: %w", err)
	}

	return nil
}

// parsePublicKeyPEM decodes a PEM-encoded public key returned by Scaleway.
// Scaleway uses non-standard PEM headers for public keys:
//   - "EC PUBLIC KEY"  → bytes are PKIX SubjectPublicKeyInfo; rewrite header.
//   - "RSA PUBLIC KEY" → bytes are PKCS#1 RSAPublicKey; parse directly.
func parsePublicKeyPEM(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return pemutil.ParseKey(pemBytes)
	}
	switch block.Type {
	case "EC PUBLIC KEY":
		block.Type = "PUBLIC KEY"
		return pemutil.ParseKey(pem.EncodeToMemory(block))
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return pemutil.ParseKey(pemBytes)
	}
}

// keyIDToURI encodes a key ID and region into a scwkms URI string.
func keyIDToURI(keyID string, region scw.Region) string {
	return uri.New(Scheme, map[string][]string{
		"key-id": {keyID},
		"region": {string(region)},
	}).String()
}

// parseKeyName parses a key identifier and returns the key ID and region.
// Accepted formats:
//   - bare UUID: "11111111-1111-1111-1111-111111111111"
//   - scwkms URI with params: "scwkms:key-id=11111111-...;region=fr-par"
//   - scwkms opaque URI:      "scwkms:11111111-..."
func parseKeyName(name string, defaultRegion scw.Region) (keyID string, region scw.Region) {
	if u, err := uri.ParseWithScheme(Scheme, name); err == nil {
		if id := u.Get("key-id"); id != "" {
			keyID = id
		} else {
			keyID = u.Opaque
		}
		if r := u.Get("region"); r != "" {
			region = scw.Region(r)
		}
	} else {
		keyID = name
	}

	if region == "" {
		region = defaultRegion
	}
	return
}

// Compile-time assertions.
var _ apiv1.KeyManager = (*ScalewayKMS)(nil)
var _ apiv1.KeyDeleter = (*ScalewayKMS)(nil)
