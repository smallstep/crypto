package platform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_transformToSoftKMS(t *testing.T) {
	tests := []struct {
		name      string
		rawuri    string
		want      string
		assertion assert.ErrorAssertionFunc
	}{
		{"scheme", "kms:", "", assert.NoError},
		{"with name", "kms:name=path/to/file.crt", "path/to/file.crt", assert.NoError},
		{"with encoded", "kms:name=%2Fpath%2Fto%2Ffile.key", "/path/to/file.key", assert.NoError},
		{"with path", "kms:path=/path/to/file.key", "/path/to/file.key", assert.NoError},
		{"with opaque", "kms:path/to/file.key", "path/to/file.key", assert.NoError},
		{"fail parse", "mackms:", "", assert.Error},
		{"fail hw", "kms:name=file.key;hw=true", "", assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transformToSoftKMS(tt.rawuri)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_transformFromSoftKMS(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		want      string
		assertion assert.ErrorAssertionFunc
	}{
		{"scheme", "", "kms:", assert.NoError},
		{"with path", "/path/to/file", "kms:name=%2Fpath%2Fto%2Ffile", assert.NoError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := transformFromSoftKMS(tt.path)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
