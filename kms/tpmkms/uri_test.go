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
		{"ok/empty", args{""}, objectProperties{uri: ""}, false},
		{"ok/key", args{"tpmkms:name=key1"}, objectProperties{uri: "tpmkms:name=key1", name: "key1"}, false},
		{"ok/attested-key", args{"tpmkms:name=key2;attest-by=ak1;qualifying-data=61626364"}, objectProperties{uri: "tpmkms:name=key2;attest-by=ak1;qualifying-data=61626364", name: "key2", attestBy: "ak1", qualifyingData: []byte{'a', 'b', 'c', 'd'}}, false},
		{"ok/ak", args{"tpmkms:name=ak1;ak=true"}, objectProperties{uri: "tpmkms:name=ak1;ak=true", name: "ak1", ak: true}, false},
		{"ok/wrong-scheme", args{nameURI: "tpmkmz:name=bla"}, objectProperties{uri: "tpmkmz:name=bla"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotO, err := parseNameURI(tt.args.nameURI)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.Equal(t, tt.wantO, gotO)
		})
	}
}
