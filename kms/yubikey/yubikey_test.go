//go:build cgo
// +build cgo

package yubikey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	return apiv1.ErrNotImplemented{}
}

func (s *stubPivKey) GenerateKey(key [24]byte, slot piv.Slot, opts piv.Key) (crypto.PublicKey, error) {
	return nil, apiv1.ErrNotImplemented{}
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
			SigningKey: "slot-id=9c",
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
			Name: "slot-id=9a",
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
