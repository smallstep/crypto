package tpmkms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_parseNameURI(t *testing.T) {
	type args struct {
		nameURI string
	}
	tests := []struct {
		name    string
		args    args
		wantO   objectProperties
		wantErr bool
	}{
		{"ok/key-without-scheme", args{"key1"}, objectProperties{name: "key1"}, false},
		{"ok/key", args{"tpmkms:name=key1"}, objectProperties{name: "key1"}, false},
		{"ok/key-without-name-key", args{"tpmkms:key1"}, objectProperties{name: "key1"}, false},
		{"ok/key-without-name-key-with-other-properties", args{"tpmkms:key1;attest-by=ak1"}, objectProperties{name: "key1", attestBy: "ak1"}, false},
		{"ok/attested-key", args{"tpmkms:name=key2;attest-by=ak1;qualifying-data=61626364"}, objectProperties{name: "key2", attestBy: "ak1", qualifyingData: []byte{'a', 'b', 'c', 'd'}}, false},
		{"ok/ak", args{"tpmkms:name=ak1;ak=true"}, objectProperties{name: "ak1", ak: true}, false},
		{"fail/empty", args{""}, objectProperties{}, true},
		{"fail/wrong-scheme", args{nameURI: "tpmkmz:name=bla"}, objectProperties{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotO, err := parseNameURI(tt.args.nameURI)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.wantO, gotO)
		})
	}
}
