package x509util

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"
)

func Test_newName(t *testing.T) {
	type args struct {
		n pkix.Name
	}
	tests := []struct {
		name string
		args args
		want Name
	}{
		{"ok", args{pkix.Name{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "The country"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "The organization"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "The organizationalUnit 1"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "The organizationalUnit 2"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "The commonName"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 5}, Value: "The serialNumber"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: "The locality 1"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: "The locality 2"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 8}, Value: "The province"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 9}, Value: "The streetAddress"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 17}, Value: "The postalCode"},
				{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("jane@example.com")}},
			},
		}}, Name{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
			ExtraNames: []DistinguishedName{
				{Type: ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("jane@example.com")}},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newName(tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestName_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    Name
		wantErr bool
	}{
		{"null", args{[]byte("null")}, Name{}, false},
		{"empty", args{[]byte("{}")}, Name{}, false},
		{"commonName", args{[]byte(`"commonName"`)}, Name{CommonName: "commonName"}, false},
		{"object", args{[]byte(`{
			"country": "The country",
			"organization": "The organization",
			"organizationalUnit": ["The organizationalUnit 1", "The organizationalUnit 2"],
			"locality": ["The locality 1", "The locality 2"],
			"province": "The province",
			"streetAddress": "The streetAddress",
			"postalCode": "The postalCode",
			"serialNumber": "The serialNumber",
			"commonName": "The commonName",
			"extraNames": [{"type":"1.2.840.113549.1.9.1", "value":"jane@example.com"}]
		}`)}, Name{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
			ExtraNames: []DistinguishedName{
				{Type: ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "jane@example.com"},
			},
		}, false},
		{"number", args{[]byte("1234")}, Name{}, true},
		{"badJSON", args{[]byte("'badJSON'")}, Name{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Name
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Name.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Name.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newSubject(t *testing.T) {
	type args struct {
		n pkix.Name
	}
	tests := []struct {
		name string
		args args
		want Subject
	}{
		{"ok", args{pkix.Name{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
			Names: []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("jane@example.com")}},
			},
		}}, Subject{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
			ExtraNames: []DistinguishedName{
				{Type: ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("jane@example.com")}},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newSubject(tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubject_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    Subject
		wantErr bool
	}{
		{"null", args{[]byte("null")}, Subject{}, false},
		{"empty", args{[]byte("{}")}, Subject{}, false},
		{"commonName", args{[]byte(`"commonName"`)}, Subject{CommonName: "commonName"}, false},
		{"object", args{[]byte(`{
			"country": "The country",
			"organization": "The organization",
			"organizationalUnit": ["The organizationalUnit 1", "The organizationalUnit 2"],
			"locality": ["The locality 1", "The locality 2"],
			"province": "The province",
			"streetAddress": "The streetAddress",
			"postalCode": "The postalCode",
			"serialNumber": "The serialNumber",
			"commonName": "The commonName"
		}`)}, Subject{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}, false},
		{"number", args{[]byte("1234")}, Subject{}, true},
		{"badJSON", args{[]byte("'badJSON'")}, Subject{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Subject
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Subject.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Subject.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSubject_Set(t *testing.T) {
	type fields struct {
		Country            MultiString
		Organization       MultiString
		OrganizationalUnit MultiString
		Locality           MultiString
		Province           MultiString
		StreetAddress      MultiString
		PostalCode         MultiString
		SerialNumber       string
		CommonName         string
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
	}{
		{"ok", fields{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}, args{&x509.Certificate{}}, &x509.Certificate{
			Subject: pkix.Name{
				Country:            []string{"The country"},
				Organization:       []string{"The organization"},
				OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
				Locality:           []string{"The locality 1", "The locality 2"},
				Province:           []string{"The province"},
				StreetAddress:      []string{"The streetAddress"},
				PostalCode:         []string{"The postalCode"},
				SerialNumber:       "The serialNumber",
				CommonName:         "The commonName",
			},
		}},
		{"overwrite", fields{
			CommonName: "The commonName",
		}, args{&x509.Certificate{}}, &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "The commonName",
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Subject{
				Country:            tt.fields.Country,
				Organization:       tt.fields.Organization,
				OrganizationalUnit: tt.fields.OrganizationalUnit,
				Locality:           tt.fields.Locality,
				Province:           tt.fields.Province,
				StreetAddress:      tt.fields.StreetAddress,
				PostalCode:         tt.fields.PostalCode,
				SerialNumber:       tt.fields.SerialNumber,
				CommonName:         tt.fields.CommonName,
			}
			s.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("Subject.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func TestSubject_IsEmpty(t *testing.T) {
	type fields struct {
		Country            MultiString
		Organization       MultiString
		OrganizationalUnit MultiString
		Locality           MultiString
		Province           MultiString
		StreetAddress      MultiString
		PostalCode         MultiString
		SerialNumber       string
		CommonName         string
		ExtraNames         []DistinguishedName
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{"ok", fields{}, true},
		{"country", fields{Country: []string{"The country"}}, false},
		{"commonName", fields{CommonName: "The commonName"}, false},
		{"all fields", fields{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Subject{
				Country:            tt.fields.Country,
				Organization:       tt.fields.Organization,
				OrganizationalUnit: tt.fields.OrganizationalUnit,
				Locality:           tt.fields.Locality,
				Province:           tt.fields.Province,
				StreetAddress:      tt.fields.StreetAddress,
				PostalCode:         tt.fields.PostalCode,
				SerialNumber:       tt.fields.SerialNumber,
				CommonName:         tt.fields.CommonName,
				ExtraNames:         tt.fields.ExtraNames,
			}
			if got := s.IsEmpty(); got != tt.want {
				t.Errorf("Subject.IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_newIssuer(t *testing.T) {
	type args struct {
		n pkix.Name
	}
	tests := []struct {
		name string
		args args
		want Issuer
	}{
		{"ok", args{pkix.Name{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}}, Issuer{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newIssuer(tt.args.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newIssuer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIssuer_UnmarshalJSON(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    args
		want    Issuer
		wantErr bool
	}{
		{"null", args{[]byte("null")}, Issuer{}, false},
		{"empty", args{[]byte("{}")}, Issuer{}, false},
		{"commonName", args{[]byte(`"commonName"`)}, Issuer{CommonName: "commonName"}, false},
		{"object", args{[]byte(`{
			"country": "The country",
			"organization": "The organization",
			"organizationalUnit": ["The organizationalUnit 1", "The organizationalUnit 2"],
			"locality": ["The locality 1", "The locality 2"],
			"province": "The province",
			"streetAddress": "The streetAddress",
			"postalCode": "The postalCode",
			"serialNumber": "The serialNumber",
			"commonName": "The commonName",
			"extraNames": [{"type":"1.2.840.113549.1.9.1", "value":"jane@example.com"}]
		}`)}, Issuer{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
			ExtraNames: []DistinguishedName{
				{Type: ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "jane@example.com"},
			},
		}, false},
		{"number", args{[]byte("1234")}, Issuer{}, true},
		{"badJSON", args{[]byte("'badJSON'")}, Issuer{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Issuer
			if err := got.UnmarshalJSON(tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("Issuer.UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Issuer.UnmarshalJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIssuer_Set(t *testing.T) {
	type fields struct {
		Country            MultiString
		Organization       MultiString
		OrganizationalUnit MultiString
		Locality           MultiString
		Province           MultiString
		StreetAddress      MultiString
		PostalCode         MultiString
		SerialNumber       string
		CommonName         string
		ExtraNames         []DistinguishedName
	}
	type args struct {
		c *x509.Certificate
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *x509.Certificate
	}{
		{"ok", fields{
			Country:            []string{"The country"},
			Organization:       []string{"The organization"},
			OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
			Locality:           []string{"The locality 1", "The locality 2"},
			Province:           []string{"The province"},
			StreetAddress:      []string{"The streetAddress"},
			PostalCode:         []string{"The postalCode"},
			SerialNumber:       "The serialNumber",
			CommonName:         "The commonName",
			ExtraNames: []DistinguishedName{
				{Type: ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "jane@example.com"},
				{Type: ObjectIdentifier{1, 2, 3, 4}, Value: "custom@example.com"},
			},
		}, args{&x509.Certificate{}}, &x509.Certificate{
			Issuer: pkix.Name{
				Country:            []string{"The country"},
				Organization:       []string{"The organization"},
				OrganizationalUnit: []string{"The organizationalUnit 1", "The organizationalUnit 2"},
				Locality:           []string{"The locality 1", "The locality 2"},
				Province:           []string{"The province"},
				StreetAddress:      []string{"The streetAddress"},
				PostalCode:         []string{"The postalCode"},
				SerialNumber:       "The serialNumber",
				CommonName:         "The commonName",
				ExtraNames: []pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("jane@example.com")}},
					{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "custom@example.com"},
				},
			},
		}},
		{"overwrite", fields{
			CommonName: "The commonName",
		}, args{&x509.Certificate{}}, &x509.Certificate{
			Issuer: pkix.Name{
				CommonName: "The commonName",
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := Issuer{
				Country:            tt.fields.Country,
				Organization:       tt.fields.Organization,
				OrganizationalUnit: tt.fields.OrganizationalUnit,
				Locality:           tt.fields.Locality,
				Province:           tt.fields.Province,
				StreetAddress:      tt.fields.StreetAddress,
				PostalCode:         tt.fields.PostalCode,
				SerialNumber:       tt.fields.SerialNumber,
				CommonName:         tt.fields.CommonName,
				ExtraNames:         tt.fields.ExtraNames,
			}
			i.Set(tt.args.c)
			if !reflect.DeepEqual(tt.args.c, tt.want) {
				t.Errorf("Issuer.Set() = %v, want %v", tt.args.c, tt.want)
			}
		})
	}
}

func Test_NewExtraNames(t *testing.T) {
	type args struct {
		atvs []pkix.AttributeTypeAndValue
	}
	tests := []struct {
		name string
		args args
		want []DistinguishedName
	}{
		{"ok", args{[]pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "The commonName"},
			{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("jane@example.com")}},
			{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "custom@example.com"},
		}}, []DistinguishedName{
			{Type: ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("jane@example.com")}},
			{Type: ObjectIdentifier{1, 2, 3, 4}, Value: "custom@example.com"},
		}},
		{"ok nil", args{nil}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewExtraNames(tt.args.atvs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("newDistinguisedNames() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_fromDistinguisedNames(t *testing.T) {
	type args struct {
		dns []DistinguishedName
	}
	tests := []struct {
		name string
		args args
		want []pkix.AttributeTypeAndValue
	}{
		{"ok", args{[]DistinguishedName{
			{Type: ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: "jane@example.com"},
			{Type: ObjectIdentifier{1, 2, 3, 4}, Value: "custom@example.com"},
		}}, []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}, Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte("jane@example.com")}},
			{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "custom@example.com"},
		}},
		{"ok nil", args{nil}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fromDistinguishedNames(tt.args.dns); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("fromDistinguisedNames() = %v, want %v", got, tt.want)
			}
		})
	}
}
