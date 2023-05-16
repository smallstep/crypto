package tpmkms

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.step.sm/crypto/kms/apiv1"
)

func TestNew(t *testing.T) {
	type args struct {
		opts apiv1.Options
	}
	tests := []struct {
		name    string
		args    args
		want    *TPMKMS
		wantErr bool
	}{
		{"ok/defaults", args{apiv1.Options{Type: "tpmkms"}}, &TPMKMS{}, false},
		{"ok/uri", args{apiv1.Options{Type: "tpmkms", URI: "tpmkms:device=/dev/tpm0;storage-directory=/tmp/tpmstorage"}}, &TPMKMS{}, false},
		{"fail/uri-scheme", args{apiv1.Options{Type: "tpmkms", URI: "tpmkmz://device=/dev/tpm0"}}, &TPMKMS{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(context.Background(), tt.args.opts)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			if assert.NotNil(t, got) {
				assert.NotNil(t, got.tpm)
			}
		})
	}
}
