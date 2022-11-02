package kms

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/awskms"
	"go.step.sm/crypto/kms/cloudkms"
	"go.step.sm/crypto/kms/softkms"
)

func TestNew(t *testing.T) {
	ctx := context.Background()

	failCloudKMS := true
	if home, err := os.UserHomeDir(); err == nil {
		file := filepath.Join(home, ".config", "gcloud", "application_default_credentials.json")
		if _, err := os.Stat(file); err == nil {
			failCloudKMS = false
		}
	}

	type args struct {
		ctx  context.Context
		opts apiv1.Options
	}
	tests := []struct {
		name     string
		skipOnCI bool
		args     args
		want     KeyManager
		wantErr  bool
	}{
		{"default", false, args{ctx, apiv1.Options{}}, &softkms.SoftKMS{}, false},
		{"softkms", false, args{ctx, apiv1.Options{Type: "softkms"}}, &softkms.SoftKMS{}, false},
		{"uri", false, args{ctx, apiv1.Options{URI: "softkms:foo=bar"}}, &softkms.SoftKMS{}, false},
		{"awskms", false, args{ctx, apiv1.Options{Type: "awskms"}}, &awskms.KMS{}, false},
		{"cloudkms", true, args{ctx, apiv1.Options{Type: "cloudkms"}}, &cloudkms.CloudKMS{}, failCloudKMS},
		{"fail validation", false, args{ctx, apiv1.Options{Type: "foobar"}}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnCI && os.Getenv("CI") == "true" {
				t.SkipNow()
			}

			got, err := New(tt.args.ctx, tt.args.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
				t.Errorf("New() = %T, want %T", got, tt.want)
			}
		})
	}
}
