package skae

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"reflect"
	"testing"

	"github.com/smallstep/go-attestation/attest"
)

func TestCreateSubjectKeyAttestationEvidenceExtension(t *testing.T) {
	t.Skip("skipping because SKAE is not complete yet")
	akCert := &x509.Certificate{
		Issuer: pkix.Name{
			CommonName: "AK Test Issuer",
		},
		SerialNumber: big.NewInt(1337),
		OCSPServer: []string{
			"https://www.example.com/ocsp/1",
			"https://www.example.com/ocsp/2",
		},
		IssuingCertificateURL: []string{
			"https://www.example.com/issuing/cert1",
		},
	}
	type args struct {
		akCert        *x509.Certificate
		params        attest.CertificationParameters
		shouldEncrypt bool
	}
	tests := []struct {
		name    string
		args    args
		want    pkix.Extension
		wantErr bool
	}{
		{
			name: "attest",
			args: args{
				akCert: akCert,
				params: attest.CertificationParameters{
					CreateAttestation: []byte("test-fake-create-attestation"),
					CreateSignature:   []byte("test-fake-create-signature"),
				},
				shouldEncrypt: false,
			},
			want: pkix.Extension{
				Id:       asn1.ObjectIdentifier{2, 23, 133, 6, 1, 1},
				Critical: false,
				Value:    []byte{},
			},
			wantErr: false,
		},
		{
			name: "enveloped-attest",
			args: args{
				akCert: akCert,
				params: attest.CertificationParameters{
					CreateAttestation: []byte("test-fake-create-attestation"),
					CreateSignature:   []byte("test-fake-create-signature"),
				},
				shouldEncrypt: true,
			},
			// want: pkix.Extension{
			// 	Id:       asn1.ObjectIdentifier{2, 23, 133, 6, 1, 1},
			// 	Critical: false,
			// 	Value:    []byte{},
			// },
			want:    pkix.Extension{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CreateSubjectKeyAttestationEvidenceExtension(tt.args.akCert, tt.args.params, tt.args.shouldEncrypt)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateSubjectKeyAttestationEvidenceExtension() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateSubjectKeyAttestationEvidenceExtension() = %v, want %v", got, tt.want)
			}
		})
	}
}
