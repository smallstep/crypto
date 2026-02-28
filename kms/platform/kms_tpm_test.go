package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_transformToTPMKMS(t *testing.T) {
	type args struct {
		u *kmsURI
	}
	tests := []struct {
		name   string
		rawuri string
		want   string
	}{
		{"scheme", "kms:", "tpmkms:"},
		{"with name", "kms:name=foo", "tpmkms:name=foo"},
		{"with ak", "kms:name=foo;ak=true", "tpmkms:ak=true;name=foo"},
		{"with ak in query", "kms:name=foo?ak=true", "tpmkms:ak=true;name=foo"},
		{"with ak false", "kms:ak=false", "tpmkms:ak=false"},
		{"with extrasValues", "kms:name=foo;foo=bar?baz=qux", "tpmkms:baz=qux;foo=bar;name=foo"},
		{"without hw", "kms:name=foo;hw=true", "tpmkms:name=foo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := mustParseURI(t, tt.rawuri)
			assert.Equal(t, tt.want, transformToTPMKMS(u))
		})
	}
}

func Test_transformFromTPMKMS(t *testing.T) {
	type args struct {
		rawuri string
	}
	tests := []struct {
		name      string
		rawuri    string
		want      string
		assertion assert.ErrorAssertionFunc
	}{
		{"scheme", "tpmkms:", "kms:", assert.NoError},
		{"with label", "tpmkms:name=foo", "kms:name=foo", assert.NoError},
		{"with ak", "tpmkms:name=foo;ak=true", "kms:ak=true;name=foo", assert.NoError},
		{"with ak on query", "tpmkms:name=foo?ak=true", "kms:ak=true;name=foo", assert.NoError},
		{"with ak false", "tpmkms:ak=false;name=foo", "kms:ak=false;name=foo", assert.NoError},
		{"fail empty", "", "", assert.Error},
		{"fail scheme", "kms:", "", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transformFromTPMKMS(tt.rawuri)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
