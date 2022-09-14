package kms

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"io/fs"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.step.sm/crypto/pemutil"
)

func generateKey(t *testing.T) (crypto.PublicKey, *bytes.Buffer) {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := pemutil.Serialize(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pub, bytes.NewBuffer(pem.EncodeToMemory(block))
}

func Test_object_FileMode(t *testing.T) {
	pub, pemData := generateKey(t)
	type fields struct {
		Path    string
		Object  interface{}
		pemData *bytes.Buffer
	}
	tests := []struct {
		name        string
		fields      fields
		wantName    string
		wantSize    int64
		wantMode    fs.FileMode
		wantModTime time.Time
		wantIsDir   bool
		wantSys     interface{}
	}{
		{"ok", fields{"path", pub, pemData}, "path", int64(pemData.Len()), 0400, time.Time{}, false, pub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &object{
				Path:    tt.fields.Path,
				Object:  tt.fields.Object,
				pemData: tt.fields.pemData,
			}
			if got := o.Name(); got != tt.wantName {
				t.Errorf("object.Name() = %v, want %v", got, tt.wantName)
			}
			if got := o.Size(); got != tt.wantSize {
				t.Errorf("object.Size() = %v, want %v", got, tt.wantSize)
			}
			if got := o.Mode(); got != tt.wantMode {
				t.Errorf("object.Mode() = %v, want %v", got, tt.wantMode)
			}
			if got := o.ModTime(); got != tt.wantModTime {
				t.Errorf("object.ModTime() = %v, want %v", got, tt.wantModTime)
			}
			if got := o.IsDir(); got != tt.wantIsDir {
				t.Errorf("object.IsDir() = %v, want %v", got, tt.wantIsDir)
			}
			if got := o.Sys(); !reflect.DeepEqual(got, tt.wantSys) {
				t.Errorf("object.Sys() = %v, want %v", got, tt.wantSys)
			}
		})
	}
}

func Test_object_load(t *testing.T) {
	pub, pemData := generateKey(t)
	type fields struct {
		Path   string
		Object interface{}
	}
	tests := []struct {
		name        string
		fields      fields
		wantPemData *bytes.Buffer
		wantErr     bool
	}{
		{"ok", fields{"path", pub}, pemData, false},
		{"fail", fields{"path", "not a key"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &object{
				Path:   tt.fields.Path,
				Object: tt.fields.Object,
			}
			if err := o.load(); (err != nil) != tt.wantErr {
				t.Errorf("object.load() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(o.pemData, tt.wantPemData) {
				t.Errorf("object.load() pemData = %s, wantPemData %s", o.pemData, tt.wantPemData)
			}
		})
	}
}

func Test_object_Stat(t *testing.T) {
	pub, pemData := generateKey(t)
	type fields struct {
		Path   string
		Object interface{}
	}
	tests := []struct {
		name    string
		fields  fields
		want    fs.FileInfo
		wantErr bool
	}{
		{"ok", fields{"path", pub}, &object{
			Path:    "path",
			Object:  pub,
			pemData: pemData,
		}, false},
		{"fail", fields{"path", "not a key"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &object{
				Path:   tt.fields.Path,
				Object: tt.fields.Object,
			}
			got, err := o.Stat()
			if (err != nil) != tt.wantErr {
				t.Errorf("object.Stat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// Normalize
			if got != nil {
				got.(*object).once = sync.Once{}
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("object.Stat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_object_Read(t *testing.T) {
	pub, pemData := generateKey(t)
	type fields struct {
		Path   string
		Object interface{}
	}
	type args struct {
		b []byte
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantN     int
		wantBytes []byte
		wantErr   bool
	}{
		{"ok", fields{"path", pub}, args{make([]byte, pemData.Len())}, pemData.Len(), pemData.Bytes(), false},
		{"empty", fields{"path", pub}, args{[]byte{}}, 0, []byte{}, false},
		{"fail", fields{"path", "not a key"}, args{[]byte{}}, 0, []byte{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &object{
				Path:   tt.fields.Path,
				Object: tt.fields.Object,
			}
			got, err := o.Read(tt.args.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("object.Read() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantN {
				t.Errorf("object.Read() = %v, wanN %v", got, tt.wantN)
			}
			if !bytes.Equal(tt.args.b, tt.wantBytes) {
				t.Errorf("object.Read() = %v, wantBytes %v", tt.args.b, tt.wantBytes)
			}
		})
	}
}

func Test_object_Close(t *testing.T) {
	pub, _ := generateKey(t)
	o := &object{
		Path:   "path",
		Object: pub,
	}
	if err := o.load(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		o       *object
		want    *object
		wantErr bool
	}{
		{"ok", o, &object{
			Path:    "path",
			Object:  nil,
			pemData: nil,
			err:     io.EOF,
		}, false},
		{"eof", o, &object{
			Path:    "path",
			Object:  nil,
			pemData: nil,
			err:     io.EOF,
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.o.Close(); (err != nil) != tt.wantErr {
				t.Errorf("object.Close() error = %v, wantErr %v", err, tt.wantErr)
			}
			// Normalize
			tt.o.once = sync.Once{}
			if !reflect.DeepEqual(tt.o, tt.want) { //nolint:govet // variable names match crypto formulae docs
				t.Errorf("object.Close() = %v, want %v", tt.o, tt.want)
			}
		})
	}
}
