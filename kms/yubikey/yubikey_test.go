//go:build cgo
// +build cgo

package yubikey

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"reflect"
	"testing"

	"github.com/go-piv/piv-go/piv"
	"github.com/pkg/errors"
	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/minica"
)

type stubPivKey struct {
	attestCA  *minica.CA
	userCA    *minica.CA
	attestMap map[piv.Slot]*x509.Certificate
	certMap   map[piv.Slot]*x509.Certificate
	signerMap map[piv.Slot]interface{}
}

//nolint:typecheck // ignore deadcode warnings
func newStubPivKey(t *testing.T) *stubPivKey {
	t.Helper()

	attestCA, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}
	userCA, err := minica.New()
	if err != nil {
		t.Fatal(err)
	}

	attSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	attCert, err := attestCA.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "attested certificate"},
		PublicKey: attSigner.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}
	userCert, err := userCA.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "test.example.org"},
		DNSNames:  []string{"test.example.org"},
		PublicKey: userSigner.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}

	return &stubPivKey{
		attestCA: attestCA,
		userCA:   userCA,
		attestMap: map[piv.Slot]*x509.Certificate{
			piv.SlotAuthentication: attCert, // 9a
		},
		certMap: map[piv.Slot]*x509.Certificate{
			piv.SlotSignature: userCert,              // 9c
			slotAttestation:   attestCA.Intermediate, // f9
		},
		signerMap: map[piv.Slot]interface{}{
			piv.SlotAuthentication: attSigner,  // 9a
			piv.SlotSignature:      userSigner, // 9c
		},
	}
}

func (s *stubPivKey) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	cert, ok := s.certMap[slot]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return cert, nil
}

func (s *stubPivKey) SetCertificate(key [24]byte, slot piv.Slot, cert *x509.Certificate) error {
	if !bytes.Equal(piv.DefaultManagementKey[:], key[:]) {
		return errors.New("missing or invalid management key")
	}
	s.certMap[slot] = cert
	return nil
}

func (s *stubPivKey) GenerateKey(key [24]byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	if !bytes.Equal(piv.DefaultManagementKey[:], key[:]) {
		return nil, errors.New("missing or invalid management key")
	}

	var signer crypto.Signer
	switch opts.Algorithm {
	case piv.AlgorithmEC256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmEC384:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmEd25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmRSA1024:
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			return nil, err
		}
		signer = key
	case piv.AlgorithmRSA2048:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		signer = key
	default:
		return nil, errors.New("unsupported algorithm")
	}

	s.signerMap[slot] = signer
	return signer.Public(), nil
}

func (s *stubPivKey) PrivateKey(slot piv.Slot, public crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error) {
	if auth.PIN != "123456" {
		return nil, errors.New("missing or invalid pin")
	}
	key, ok := s.signerMap[slot]
	if !ok {
		return nil, errors.New("private key not found")
	}
	return key, nil
}

func (s *stubPivKey) Attest(slot piv.Slot) (*x509.Certificate, error) {
	cert, ok := s.attestMap[slot]
	if !ok {
		return nil, errors.New("certificate not found")
	}
	return cert, nil
}

func (s *stubPivKey) Close() error {
	return nil
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	pOpen := pivOpen
	pCards := pivCards
	t.Cleanup(func() {
		pivOpen = pOpen
		pivCards = pCards
	})

	yk := newStubPivKey(t)

	okPivCards := func() ([]string, error) {
		return []string{"Yubico YubiKey OTP+FIDO+CCID"}, nil
	}
	failPivCards := func() ([]string, error) {
		return nil, errors.New("error reading cards")
	}
	failNoPivCards := func() ([]string, error) {
		return []string{}, nil
	}

	okPivOpen := func(card string) (pivKey, error) {
		return yk, nil
	}
	failPivOpen := func(card string) (pivKey, error) {
		return nil, errors.New("error opening card")
	}

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		setup   func()
		want    *YubiKey
		wantErr bool
	}{
		{"ok", args{ctx, apiv1.Options{}}, func() {
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", managementKey: piv.DefaultManagementKey}, false},
		{"ok with uri", args{ctx, apiv1.Options{
			URI: "yubikey:pin-value=111111;management-key=001122334455667788990011223344556677889900112233",
		}}, func() {
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "111111", managementKey: [24]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33}}, false},
		{"ok with Pin", args{ctx, apiv1.Options{Pin: "222222"}}, func() {
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "222222", managementKey: piv.DefaultManagementKey}, false},
		{"ok with ManagementKey", args{ctx, apiv1.Options{ManagementKey: "001122334455667788990011223344556677889900112233"}}, func() {
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, &YubiKey{yk: yk, pin: "123456", managementKey: [24]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33}}, false},
		{"fail uri", args{ctx, apiv1.Options{URI: "badschema:"}}, func() {
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail management key", args{ctx, apiv1.Options{URI: "yubikey:management-key=xxyyzz"}}, func() {
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail management key size", args{ctx, apiv1.Options{URI: "yubikey:management-key=00112233"}}, func() {
			pivCards = okPivCards
			pivOpen = okPivOpen
		}, nil, true},
		{"fail pivCards", args{ctx, apiv1.Options{}}, func() {
			pivCards = failPivCards
			pivOpen = okPivOpen

		}, nil, true},
		{"fail no pivCards", args{ctx, apiv1.Options{}}, func() {
			pivCards = failNoPivCards
			pivOpen = okPivOpen

		}, nil, true},
		{"fail pivOpen", args{ctx, apiv1.Options{}}, func() {
			pivCards = okPivCards
			pivOpen = failPivOpen
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()

			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_LoadCertificate(t *testing.T) {
	yk := newStubPivKey(t)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey [24]byte
	}
	type args struct {
		req *apiv1.LoadCertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *x509.Certificate
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.LoadCertificateRequest{
			Name: "yubikey:slot-id=9c",
		}}, yk.certMap[piv.SlotSignature], false},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.LoadCertificateRequest{
			Name: "slot-id=9c",
		}}, nil, true},
		{"fail certificate", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.LoadCertificateRequest{
			Name: "yubikey:slot-id=85",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.LoadCertificate(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.LoadCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.LoadCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_StoreCertificate(t *testing.T) {
	yk := newStubPivKey(t)

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := yk.userCA.Sign(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "foo.example.org"},
		DNSNames:  []string{"foo.example.org"},
		PublicKey: signer.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}

	type fields struct {
		yk            pivKey
		pin           string
		managementKey [24]byte
	}
	type args struct {
		req *apiv1.StoreCertificateRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.StoreCertificateRequest{
			Name:        "yubikey:slot-id=9c",
			Certificate: cert,
		}}, false},
		{"fail nil", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.StoreCertificateRequest{
			Name: "yubikey:slot-id=9c",
		}}, true},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.StoreCertificateRequest{
			Name:        "slot-id=9c",
			Certificate: cert,
		}}, true},
		{"fail setCertificate", fields{yk, "123456", [24]byte{}}, args{&apiv1.StoreCertificateRequest{
			Name:        "yubikey:slot-id=9c",
			Certificate: cert,
		}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			if err := k.StoreCertificate(tt.args.req); (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.StoreCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestYubiKey_GetPublicKey(t *testing.T) {
	yk := newStubPivKey(t)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey [24]byte
	}
	type args struct {
		req *apiv1.GetPublicKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.GetPublicKeyRequest{
			Name: "yubikey:slot-id=9c",
		}}, yk.certMap[piv.SlotSignature].PublicKey, false},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.GetPublicKeyRequest{
			Name: "slot-id=9c",
		}}, nil, true},
		{"fail getPublicKey", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.GetPublicKeyRequest{
			Name: "yubikey:slot-id=85",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.GetPublicKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.GetPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.GetPublicKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_CreateKey(t *testing.T) {
	yk := newStubPivKey(t)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey [24]byte
	}
	type args struct {
		req *apiv1.CreateKeyRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantFn  func() *apiv1.CreateKeyResponse
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok default", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=9c",
				PublicKey: yk.signerMap[slotMapping["9c"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=9c",
				},
			}
		}, false},
		{"ok p256", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok p384", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA384,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok ed25519", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.PureEd25519,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok rsa", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok rsa 1024", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               1024,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"ok rsa 2048", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               2048,
		}}, func() *apiv1.CreateKeyResponse {
			return &apiv1.CreateKeyResponse{
				Name:      "yubikey:slot-id=82",
				PublicKey: yk.signerMap[slotMapping["82"]].(crypto.Signer).Public(),
				CreateSignerRequest: apiv1.CreateSignerRequest{
					SigningKey: "yubikey:slot-id=82",
				},
			}
		}, false},
		{"fail rsa 4096", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SHA256WithRSA,
			Bits:               4096,
		}}, func() *apiv1.CreateKeyResponse { return nil }, true},
		{"fail getSignatureAlgorithm", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.SignatureAlgorithm(100),
		}}, func() *apiv1.CreateKeyResponse { return nil }, true},
		{"fail getSlotAndName", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:foo=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse { return nil }, true},
		{"fail generateKey", fields{yk, "123456", [24]byte{}}, args{&apiv1.CreateKeyRequest{
			Name:               "yubikey:slot-id=82",
			SignatureAlgorithm: apiv1.ECDSAWithSHA256,
		}}, func() *apiv1.CreateKeyResponse { return nil }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "fail getSlotAndName" {
				t.Log(tt.name)
			}
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.CreateKey(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.CreateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			want := tt.wantFn()
			if !reflect.DeepEqual(got, want) {
				t.Errorf("YubiKey.CreateKey() = %v, want %v", got, want)
			}
		})
	}
}

func TestYubiKey_CreateSigner(t *testing.T) {
	yk := newStubPivKey(t)

	ykFail := newStubPivKey(t)
	ykFail.signerMap[piv.SlotSignature] = "not-a-signer"

	type fields struct {
		yk            pivKey
		pin           string
		managementKey [24]byte
	}
	type args struct {
		req *apiv1.CreateSignerRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    crypto.Signer
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=9c",
		}}, yk.signerMap[piv.SlotSignature].(crypto.Signer), false},
		{"ok with pin", fields{yk, "", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=9c?pin-value=123456",
		}}, yk.signerMap[piv.SlotSignature].(crypto.Signer), false},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=%%FF",
		}}, nil, true},
		{"fail getPublicKey", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=85",
		}}, nil, true},
		{"fail privateKey", fields{yk, "654321", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=9c",
		}}, nil, true},
		{"fail signer", fields{ykFail, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateSignerRequest{
			SigningKey: "yubikey:slot-id=9c",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.CreateSigner(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.CreateSigner() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.CreateSigner() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_CreateAttestation(t *testing.T) {
	yk := newStubPivKey(t)

	ykFail := newStubPivKey(t)
	delete(ykFail.certMap, slotAttestation)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey [24]byte
	}
	type args struct {
		req *apiv1.CreateAttestationRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *apiv1.CreateAttestationResponse
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey:slot-id=9a",
		}}, &apiv1.CreateAttestationResponse{
			Certificate:      yk.attestMap[piv.SlotAuthentication],
			CertificateChain: []*x509.Certificate{yk.attestCA.Intermediate},
			PublicKey:        yk.attestMap[piv.SlotAuthentication].PublicKey,
		}, false},
		{"fail getSlot", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey://:slot-id=9a",
		}}, nil, true},
		{"fail attest", fields{yk, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey:slot-id=85",
		}}, nil, true},
		{"fail certificate", fields{ykFail, "123456", piv.DefaultManagementKey}, args{&apiv1.CreateAttestationRequest{
			Name: "yubikey:slot-id=9a",
		}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			got, err := k.CreateAttestation(tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.CreateAttestation() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("YubiKey.CreateAttestation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestYubiKey_Close(t *testing.T) {
	yk := newStubPivKey(t)

	type fields struct {
		yk            pivKey
		pin           string
		managementKey [24]byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{"ok", fields{yk, "123456", piv.DefaultManagementKey}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &YubiKey{
				yk:            tt.fields.yk,
				pin:           tt.fields.pin,
				managementKey: tt.fields.managementKey,
			}
			if err := k.Close(); (err != nil) != tt.wantErr {
				t.Errorf("YubiKey.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
