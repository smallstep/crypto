package utils

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
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

// Set content to be read from mock STDIN
func setStdinContent(t *testing.T, content string) (cleanup func()) {
	f, err := os.CreateTemp("" /* dir */, "utils-read-test")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)
	old := stdin
	stdin = f

	return func() {
		stdin = old
		require.NoError(t, f.Close())
		require.NoError(t, os.Remove(f.Name()))
	}
}

func TestReadFromStdin(t *testing.T) {
	cleanup := setStdinContent(t, "input on STDIN")
	t.Cleanup(func() {
		cleanup()
	})

	b, err := ReadFile(stdinFilename)
	require.NoError(t, err)
	require.Equal(t, "input on STDIN", string(b))
}

// Sets STDIN to a file that is already closed, and thus fails
// to be read from.
func setFailingStdin(t *testing.T) (cleanup func()) {
	f, err := os.CreateTemp("" /* dir */, "utils-read-test")
	require.NoError(t, err)
	err = f.Close()
	require.NoError(t, err)
	old := stdin
	stdin = f

	return func() {
		stdin = old
		require.NoError(t, os.Remove(f.Name()))
	}
}

func TestReadFromStdinFails(t *testing.T) {
	cleanup := setFailingStdin(t)
	t.Cleanup(func() {
		cleanup()
	})

	b, err := ReadFile(stdinFilename)
	require.Error(t, err)
	require.Empty(t, b)
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

func TestReadPasswordFromStdin(t *testing.T) {
	cleanup := setStdinContent(t, "this-is-a-secret-testing-password")
	t.Cleanup(func() {
		cleanup()
	})

	b, err := ReadPasswordFromFile(stdinFilename)
	require.NoError(t, err)
	require.Equal(t, "this-is-a-secret-testing-password", string(b))
}

func TestWriteFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "go-tests")
	require.NoError(t, err)
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
	wantErr := errors.New("the error")
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
			require.Equal(t, tt.wantErr, err)
		})
	}
}
