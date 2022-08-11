package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pkg/errors"
)

func TestReadFile(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok", args{"testdata/pass1.txt"}, []byte("brandy-guidon-basin-ishmael-sedge-ducting"), false},
		{"missing", args{"testdata/missing.txt"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadFile(tt.args.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadPasswordFromFile(t *testing.T) {
	type args struct {
		filename string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok", args{"testdata/pass1.txt"}, []byte("brandy-guidon-basin-ishmael-sedge-ducting"), false},
		{"trim", args{"testdata/pass2.txt"}, []byte("benumb-eyepiece-stale-revers-marital-mimesis"), false},
		{"missing", args{"testdata/missing.txt"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadPasswordFromFile(tt.args.filename)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadPasswordFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ReadPasswordFromFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "go-tests")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	type args struct {
		filename string
		data     []byte
		perm     os.FileMode
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"ok", args{filepath.Join(tmpDir, "test.txt"), []byte("foo"), 0600}, false},
		{"fail", args{tmpDir, []byte("foo"), 0600}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := WriteFile(tt.args.filename, tt.args.data, tt.args.perm); (err != nil) != tt.wantErr {
				t.Errorf("WriteFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_maybeUnwrap(t *testing.T) {
	wantErr := fmt.Errorf("the error")

	type args struct {
		err error
	}
	tests := []struct {
		name    string
		args    args
		wantErr error
	}{
		{"wrapped", args{errors.WithMessage(wantErr, "wrapped error")}, wantErr},
		{"not wrapped", args{wantErr}, wantErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := maybeUnwrap(tt.args.err)
			if !reflect.DeepEqual(err, tt.wantErr) {
				t.Errorf("maybeUnwrap() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
