package kms

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"testing"

	"go.step.sm/crypto/kms/apiv1"
	"go.step.sm/crypto/kms/softkms"
)

type fakeCM struct {
	softkms.SoftKMS
}

func (f *fakeCM) GetPublicKey(req *apiv1.GetPublicKeyRequest) (crypto.PublicKey, error) {
	if req.Name == "fail" {
		return nil, errors.New("an error")
	}
	return []byte(req.Name), nil
}

func (f *fakeCM) LoadCertificate(req *apiv1.LoadCertificateRequest) (*x509.Certificate, error) {
	if req.Name == "fail" {
		return nil, errors.New("an error")
	}

	return &x509.Certificate{Subject: pkix.Name{CommonName: req.Name}}, nil
}

func (f *fakeCM) StoreCertificate(req *apiv1.StoreCertificateRequest) error {
	if req.Name == "fail" {
		return errors.New("an error")
	}

	return nil
}

func TestMain(m *testing.M) {
	apiv1.Register(apiv1.Type("fake"), func(ctx context.Context, opts apiv1.Options) (apiv1.KeyManager, error) {
		return &fakeCM{}, nil
	})
	os.Exit(m.Run())
}

func Test_new(t *testing.T) {
	ctx := context.TODO()
	type args struct {
		ctx    context.Context
		kmsuri string
	}
	tests := []struct {
		name    string
		args    args
		want    *kmsfs
		wantErr bool
	}{
		{"ok empty", args{ctx, ""}, &kmsfs{}, false},
		{"ok softkms", args{ctx, "softkms:"}, &kmsfs{
			KeyManager: &softkms.SoftKMS{},
		}, false},
		{"fail", args{ctx, "fail:"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newFS(tt.args.ctx, tt.args.kmsuri)
			if (err != nil) != tt.wantErr {
				t.Errorf("new() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("new() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_kmsfs_getKMS(t *testing.T) {
	type fields struct {
		KeyManager apiv1.KeyManager
	}
	type args struct {
		kmsuri string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    apiv1.KeyManager
		wantErr bool
	}{
		{"ok empty", fields{nil}, args{""}, &softkms.SoftKMS{}, false},
		{"ok softkms", fields{&softkms.SoftKMS{}}, args{""}, &softkms.SoftKMS{}, false},
		{"ok softkms with uri", fields{nil}, args{"softkms:"}, &softkms.SoftKMS{}, false},
		{"fail", fields{nil}, args{"fail:"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &kmsfs{
				KeyManager: tt.fields.KeyManager,
			}
			got, err := f.getKMS(tt.args.kmsuri)
			if (err != nil) != tt.wantErr {
				t.Errorf("kmsfs.getKMS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("kmsfs.getKMS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_loadKMS(t *testing.T) {
	ctx := context.TODO()
	type args struct {
		ctx    context.Context
		kmsuri string
	}
	tests := []struct {
		name    string
		args    args
		want    apiv1.KeyManager
		wantErr bool
	}{
		{"ok", args{ctx, "softkms:"}, &softkms.SoftKMS{}, false},
		{"ok empty", args{ctx, ""}, &softkms.SoftKMS{}, false},
		{"fail", args{ctx, "fail:"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadKMS(tt.args.ctx, tt.args.kmsuri)
			if (err != nil) != tt.wantErr {
				t.Errorf("loadKMS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("loadKMS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_openError(t *testing.T) {
	type args struct {
		name string
		err  error
	}
	tests := []struct {
		name string
		args args
		want *fs.PathError
	}{
		{"ok", args{"name", errors.New("an error")}, &fs.PathError{
			Path: "name", Op: "open", Err: errors.New("an error"),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := openError(tt.args.name, tt.args.err); !reflect.DeepEqual(got, tt.want) { //nolint:govet // variable names match crypto formulae docs
				t.Errorf("openError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertFS(t *testing.T) {
	ctx := context.TODO()
	type args struct {
		ctx    context.Context
		kmsuri string
	}
	tests := []struct {
		name    string
		args    args
		want    fs.FS
		wantErr bool
	}{
		{"ok", args{ctx, "fake:"}, &certFS{kmsfs: &kmsfs{KeyManager: &fakeCM{}}}, false},
		{"fail", args{ctx, "fail:"}, nil, true},
		{"fail not implemented", args{ctx, "softkms:"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CertFS(tt.args.ctx, tt.args.kmsuri)
			if (err != nil) != tt.wantErr {
				t.Errorf("CertFS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertFS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_certFS_Open(t *testing.T) {
	fake := &kmsfs{KeyManager: &fakeCM{}}
	type fields struct {
		kmsfs *kmsfs
	}
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    fs.File
		wantErr bool
	}{
		{"ok", fields{fake}, args{"foo"}, &object{
			Path:   "foo",
			Object: &x509.Certificate{Subject: pkix.Name{CommonName: "foo"}},
		}, false},
		{"ok load", fields{&kmsfs{}}, args{"fake:foo"}, &object{
			Path:   "fake:foo",
			Object: &x509.Certificate{Subject: pkix.Name{CommonName: "fake:foo"}},
		}, false},
		{"fail fake", fields{fake}, args{"fail"}, nil, true},
		{"fail unregistered", fields{&kmsfs{}}, args{"fail:"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &certFS{
				kmsfs: tt.fields.kmsfs,
			}
			got, err := f.Open(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("certFS.Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("certFS.Open() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyFS(t *testing.T) {
	ctx := context.TODO()
	type args struct {
		ctx    context.Context
		kmsuri string
	}
	tests := []struct {
		name    string
		args    args
		want    fs.FS
		wantErr bool
	}{
		{"ok", args{ctx, "fake:"}, &keyFS{kmsfs: &kmsfs{KeyManager: &fakeCM{}}}, false},
		{"fail", args{ctx, "fail:"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := KeyFS(tt.args.ctx, tt.args.kmsuri)
			if (err != nil) != tt.wantErr {
				t.Errorf("KeyFS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("KeyFS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_keyFS_Open(t *testing.T) {
	fake := &kmsfs{KeyManager: &fakeCM{}}
	type fields struct {
		kmsfs *kmsfs
	}
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    fs.File
		wantErr bool
	}{
		{"ok", fields{fake}, args{"foo"}, &object{
			Path:   "foo",
			Object: []byte("foo"),
		}, false},
		{"ok load", fields{&kmsfs{}}, args{"fake:foo"}, &object{
			Path:   "fake:foo",
			Object: []byte("fake:foo"),
		}, false},
		{"fail fake", fields{fake}, args{"fail"}, nil, true},
		{"fail unregistered", fields{&kmsfs{}}, args{"fail:"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &keyFS{
				kmsfs: tt.fields.kmsfs,
			}
			got, err := f.Open(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("keyFS.Open() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("keyFS.Open() = %v, want %v", got, tt.want)
			}
		})
	}
}
