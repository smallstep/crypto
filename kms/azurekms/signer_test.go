package azurekms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/kms/apiv1"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

type FuncMatcher func(x interface{}) bool

func (f FuncMatcher) Matches(x interface{}) bool {
	return f(x)
}

func (FuncMatcher) String() string { return "matches using a function" }

func TestNewSigner(t *testing.T) {
	key, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	jwk := createJWK(t, pub)

	m := mockClient(t)
	m.EXPECT().GetKey(gomock.Any(), "my-key", "", nil).Return(azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: jwk,
		},
	}, nil)
	m.EXPECT().GetKey(gomock.Any(), "my-key", "my-version", nil).Return(azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: jwk,
		},
	}, nil)
	m.EXPECT().GetKey(gomock.Any(), "my-key", "my-version", nil).Return(azkeys.GetKeyResponse{
		KeyBundle: azkeys.KeyBundle{
			Key: jwk,
		},
	}, nil)
	m.EXPECT().GetKey(gomock.Any(), "not-found", "my-version", nil).Return(azkeys.GetKeyResponse{}, errTest)

	client := newLazyClient("vault.azure.net", func(vaultURL string) (KeyVaultClient, error) {
		if vaultURL == "https://fail.vault.azure.net/" {
			return nil, errTest
		}
		return m, nil
	})

	var noOptions defaultOptions
	type args struct {
		client     *lazyClient
		signingKey string
		defaults   defaultOptions
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"ok", args{client, "azurekms:vault=my-vault;name=my-key", noOptions}, &Signer{
			client:    m,
			name:      "my-key",
			version:   "",
			publicKey: pub,
		}, false},
		{"ok with version", args{client, "azurekms:name=my-key;vault=my-vault?version=my-version", noOptions}, &Signer{
			client:    m,
			name:      "my-key",
			version:   "my-version",
			publicKey: pub,
		}, false},
		{"ok with options", args{client, "azurekms:name=my-key?version=my-version", defaultOptions{Vault: "my-vault", ProtectionLevel: apiv1.HSM}}, &Signer{
			client:    m,
			name:      "my-key",
			version:   "my-version",
			publicKey: pub,
		}, false},
		{"fail GetKey", args{client, "azurekms:name=not-found;vault=my-vault?version=my-version", noOptions}, nil, true},
		{"fail vault", args{client, "azurekms:name=not-found;vault=", noOptions}, nil, true},
		{"fail id", args{client, "azurekms:name=;vault=my-vault?version=my-version", noOptions}, nil, true},
		{"fail get client", args{client, "azurekms:vault=fail;name=my-key", noOptions}, nil, true},
		{"fail scheme", args{client, "kms:name=not-found;vault=my-vault?version=my-version", noOptions}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSigner(tt.args.client, tt.args.signingKey, tt.args.defaults)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Public(t *testing.T) {
	key, err := keyutil.GenerateDefaultSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()

	type fields struct {
		publicKey crypto.PublicKey
	}
	tests := []struct {
		name   string
		fields fields
		want   crypto.PublicKey
	}{
		{"ok", fields{pub}, pub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				publicKey: tt.fields.publicKey,
			}
			if got := s.Public(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.Public() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Sign(t *testing.T) {
	sign := func(kty, crv string, bits int, opts crypto.SignerOpts) (crypto.PublicKey, []byte, []byte, []byte) {
		key, err := keyutil.GenerateSigner(kty, crv, bits)
		if err != nil {
			t.Fatal(err)
		}
		h := opts.HashFunc().New()
		h.Write([]byte("random-data"))
		sum := h.Sum(nil)

		var sig, resultSig []byte
		if priv, ok := key.(*ecdsa.PrivateKey); ok {
			r, s, err := ecdsa.Sign(rand.Reader, priv, sum)
			if err != nil {
				t.Fatal(err)
			}
			curveBits := priv.Params().BitSize
			keyBytes := curveBits / 8
			if curveBits%8 > 0 {
				keyBytes++
			}
			rBytes := r.Bytes()
			rBytesPadded := make([]byte, keyBytes)
			copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

			sBytes := s.Bytes()
			sBytesPadded := make([]byte, keyBytes)
			copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)
			//nolint:gocritic,makezero // rBytesPadded is initialized
			resultSig = append(rBytesPadded, sBytesPadded...)

			var b cryptobyte.Builder
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1BigInt(r)
				b.AddASN1BigInt(s)
			})
			sig, err = b.Bytes()
			if err != nil {
				t.Fatal(err)
			}
		} else {
			sig, err = key.Sign(rand.Reader, sum, opts)
			if err != nil {
				t.Fatal(err)
			}
			resultSig = sig
		}

		return key.Public(), h.Sum(nil), resultSig, sig
	}

	p256, p256Digest, p256ResultSig, p256Sig := sign("EC", "P-256", 0, crypto.SHA256)
	p384, p384Digest, p386ResultSig, p384Sig := sign("EC", "P-384", 0, crypto.SHA384)
	p521, p521Digest, p521ResultSig, p521Sig := sign("EC", "P-521", 0, crypto.SHA512)
	rsaSHA256, rsaSHA256Digest, rsaSHA256ResultSig, rsaSHA256Sig := sign("RSA", "", 2048, crypto.SHA256)
	rsaSHA384, rsaSHA384Digest, rsaSHA384ResultSig, rsaSHA384Sig := sign("RSA", "", 2048, crypto.SHA384)
	rsaSHA512, rsaSHA512Digest, rsaSHA512ResultSig, rsaSHA512Sig := sign("RSA", "", 2048, crypto.SHA512)
	rsaPSSSHA256, rsaPSSSHA256Digest, rsaPSSSHA256ResultSig, rsaPSSSHA256Sig := sign("RSA", "", 2048, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	rsaPSSSHA384, rsaPSSSHA384Digest, rsaPSSSHA384ResultSig, rsaPSSSHA384Sig := sign("RSA", "", 2048, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA512,
	})
	rsaPSSSHA512, rsaPSSSHA512Digest, rsaPSSSHA512ResultSig, rsaPSSSHA512Sig := sign("RSA", "", 2048, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA512,
	})

	ed25519Key, err := keyutil.GenerateSigner("OKP", "Ed25519", 0)
	if err != nil {
		t.Fatal(err)
	}

	client := mockClient(t)
	expects := []struct {
		name       string
		keyVersion string
		alg        azkeys.JSONWebKeySignatureAlgorithm
		digest     []byte
		result     azkeys.SignResponse
		err        error
	}{
		{"P-256", "", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: p256ResultSig},
		}, nil},
		{"P-384", "my-version", azkeys.JSONWebKeySignatureAlgorithmES384, p384Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: p386ResultSig},
		}, nil},
		{"P-521", "my-version", azkeys.JSONWebKeySignatureAlgorithmES512, p521Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: p521ResultSig},
		}, nil},
		{"RSA SHA256", "", azkeys.JSONWebKeySignatureAlgorithmRS256, rsaSHA256Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: rsaSHA256ResultSig},
		}, nil},
		{"RSA SHA384", "", azkeys.JSONWebKeySignatureAlgorithmRS384, rsaSHA384Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: rsaSHA384ResultSig},
		}, nil},
		{"RSA SHA512", "", azkeys.JSONWebKeySignatureAlgorithmRS512, rsaSHA512Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: rsaSHA512ResultSig},
		}, nil},
		{"RSA-PSS SHA256", "", azkeys.JSONWebKeySignatureAlgorithmPS256, rsaPSSSHA256Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: rsaPSSSHA256ResultSig},
		}, nil},
		{"RSA-PSS SHA384", "", azkeys.JSONWebKeySignatureAlgorithmPS384, rsaPSSSHA384Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: rsaPSSSHA384ResultSig},
		}, nil},
		{"RSA-PSS SHA512", "", azkeys.JSONWebKeySignatureAlgorithmPS512, rsaPSSSHA512Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: rsaPSSSHA512ResultSig},
		}, nil},
		// Errors
		{"fail Sign", "", azkeys.JSONWebKeySignatureAlgorithmRS256, rsaSHA256Digest, azkeys.SignResponse{}, errTest},
		{"fail sign length", "", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: rsaSHA256ResultSig},
		}, nil},
		{"fail base64", "", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, azkeys.SignResponse{
			KeyOperationResult: azkeys.KeyOperationResult{Result: func() []byte { return []byte("😎") }()},
		}, nil},
	}
	for _, e := range expects {
		ee := e
		client.EXPECT().Sign(gomock.Any(), "my-key", e.keyVersion, FuncMatcher(func(x interface{}) bool {
			p, ok := x.(azkeys.SignParameters)
			return ok && *p.Algorithm == ee.alg && bytes.Equal(p.Value, ee.digest)
		}), nil).Return(e.result, e.err)
	}

	type fields struct {
		client    KeyVaultClient
		name      string
		version   string
		publicKey crypto.PublicKey
	}
	type args struct {
		rand   io.Reader
		digest []byte
		opts   crypto.SignerOpts
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok P-256", fields{client, "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, p256Sig, false},
		{"ok P-384", fields{client, "my-key", "my-version", p384}, args{
			rand.Reader, p384Digest, crypto.SHA384,
		}, p384Sig, false},
		{"ok P-521", fields{client, "my-key", "my-version", p521}, args{
			rand.Reader, p521Digest, crypto.SHA512,
		}, p521Sig, false},
		{"ok RSA SHA256", fields{client, "my-key", "", rsaSHA256}, args{
			rand.Reader, rsaSHA256Digest, crypto.SHA256,
		}, rsaSHA256Sig, false},
		{"ok RSA SHA384", fields{client, "my-key", "", rsaSHA384}, args{
			rand.Reader, rsaSHA384Digest, crypto.SHA384,
		}, rsaSHA384Sig, false},
		{"ok RSA SHA512", fields{client, "my-key", "", rsaSHA512}, args{
			rand.Reader, rsaSHA512Digest, crypto.SHA512,
		}, rsaSHA512Sig, false},
		{"ok RSA-PSS SHA256", fields{client, "my-key", "", rsaPSSSHA256}, args{
			rand.Reader, rsaPSSSHA256Digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthAuto,
				Hash:       crypto.SHA256,
			},
		}, rsaPSSSHA256Sig, false},
		{"ok RSA-PSS SHA384", fields{client, "my-key", "", rsaPSSSHA384}, args{
			rand.Reader, rsaPSSSHA384Digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       crypto.SHA384,
			},
		}, rsaPSSSHA384Sig, false},
		{"ok RSA-PSS SHA512", fields{client, "my-key", "", rsaPSSSHA512}, args{
			rand.Reader, rsaPSSSHA512Digest, &rsa.PSSOptions{
				SaltLength: 64,
				Hash:       crypto.SHA512,
			},
		}, rsaPSSSHA512Sig, false},
		{"fail Sign", fields{client, "my-key", "", rsaSHA256}, args{
			rand.Reader, rsaSHA256Digest, crypto.SHA256,
		}, nil, true},
		{"fail sign length", fields{client, "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, nil, true},
		{"fail base64", fields{client, "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, nil, true},
		{"fail RSA-PSS salt length", fields{client, "my-key", "", rsaPSSSHA256}, args{
			rand.Reader, rsaPSSSHA256Digest, &rsa.PSSOptions{
				SaltLength: 64,
				Hash:       crypto.SHA256,
			},
		}, nil, true},
		{"fail RSA Hash", fields{client, "my-key", "", rsaSHA256}, args{
			rand.Reader, rsaSHA256Digest, crypto.SHA1,
		}, nil, true},
		{"fail ECDSA Hash", fields{client, "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.MD5,
		}, nil, true},
		{"fail Ed25519", fields{client, "my-key", "", ed25519Key}, args{
			rand.Reader, []byte("message"), crypto.Hash(0),
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:    tt.fields.client,
				name:      tt.fields.name,
				version:   tt.fields.version,
				publicKey: tt.fields.publicKey,
			}
			got, err := s.Sign(tt.args.rand, tt.args.digest, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Signer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSigner_Sign_signWithRetry(t *testing.T) {
	sign := func(kty, crv string, bits int, opts crypto.SignerOpts) (crypto.PublicKey, []byte, []byte, []byte) {
		key, err := keyutil.GenerateSigner(kty, crv, bits)
		if err != nil {
			t.Fatal(err)
		}
		h := opts.HashFunc().New()
		h.Write([]byte("random-data"))
		sum := h.Sum(nil)

		var sig, resultSig []byte
		if priv, ok := key.(*ecdsa.PrivateKey); ok {
			r, s, err := ecdsa.Sign(rand.Reader, priv, sum)
			if err != nil {
				t.Fatal(err)
			}
			curveBits := priv.Params().BitSize
			keyBytes := curveBits / 8
			if curveBits%8 > 0 {
				keyBytes++
			}
			rBytes := r.Bytes()
			rBytesPadded := make([]byte, keyBytes)
			copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

			sBytes := s.Bytes()
			sBytesPadded := make([]byte, keyBytes)
			copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)
			//nolint:gocritic,makezero // rBytesPadded is initialized
			resultSig = append(rBytesPadded, sBytesPadded...)

			var b cryptobyte.Builder
			b.AddASN1(asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1BigInt(r)
				b.AddASN1BigInt(s)
			})
			sig, err = b.Bytes()
			if err != nil {
				t.Fatal(err)
			}
		} else {
			sig, err = key.Sign(rand.Reader, sum, opts)
			if err != nil {
				t.Fatal(err)
			}
			resultSig = sig
		}

		return key.Public(), h.Sum(nil), resultSig, sig
	}

	p256, p256Digest, p256ResultSig, p256Sig := sign("EC", "P-256", 0, crypto.SHA256)
	okResult := azkeys.SignResponse{
		KeyOperationResult: azkeys.KeyOperationResult{Result: p256ResultSig},
	}
	failResult := azkeys.SignResponse{}
	retryError := &azcore.ResponseError{StatusCode: 429}

	client := mockClient(t)
	expects := []struct {
		name       string
		keyVersion string
		alg        azkeys.JSONWebKeySignatureAlgorithm
		digest     []byte
		result     azkeys.SignResponse
		err        error
	}{
		{"ok 1", "", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, failResult, retryError},
		{"ok 2", "", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, failResult, retryError},
		{"ok 3", "", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, failResult, retryError},
		{"ok 4", "", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, okResult, nil},
		{"fail", "fail-version", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, failResult, retryError},
		{"fail", "fail-version", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, failResult, retryError},
		{"fail", "fail-version", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, failResult, retryError},
		{"fail", "fail-version", azkeys.JSONWebKeySignatureAlgorithmES256, p256Digest, failResult, retryError},
	}
	for _, e := range expects {
		ee := e
		client.EXPECT().Sign(gomock.Any(), "my-key", e.keyVersion, FuncMatcher(func(x interface{}) bool {
			p, ok := x.(azkeys.SignParameters)
			return ok && *p.Algorithm == ee.alg && bytes.Equal(p.Value, ee.digest)
		}), nil).Return(e.result, e.err)
	}

	type fields struct {
		client    KeyVaultClient
		name      string
		version   string
		publicKey crypto.PublicKey
	}
	type args struct {
		rand   io.Reader
		digest []byte
		opts   crypto.SignerOpts
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok", fields{client, "my-key", "", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, p256Sig, false},
		{"fail", fields{client, "my-key", "fail-version", p256}, args{
			rand.Reader, p256Digest, crypto.SHA256,
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Signer{
				client:    tt.fields.client,
				name:      tt.fields.name,
				version:   tt.fields.version,
				publicKey: tt.fields.publicKey,
			}
			got, err := s.Sign(tt.args.rand, tt.args.digest, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Signer.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Signer.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}
