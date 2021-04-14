package x509util

import (
	"reflect"
	"testing"
)

func TestReadCertPool(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name         string
		args         args
		wantSubjects [][]byte
		wantErr      bool
	}{
		{"ok dir", args{"testdata/capath"}, [][]byte{[]byte("0\x191\x170\x15\x06\x03U\x04\x03\x13\x0ESmallstep CA 1"), []byte("0\x191\x170\x15\x06\x03U\x04\x03\x13\x0ESmallstep CA 2")}, false},
		{"ok dir 2", args{"testdata/capath2"}, [][]byte{[]byte("0\x191\x170\x15\x06\x03U\x04\x03\x13\x0ESmallstep CA 1"), []byte("0\x191\x170\x15\x06\x03U\x04\x03\x13\x0ESmallstep CA 2")}, false},
		{"ok file", args{"testdata/capath/cert.pem"}, [][]byte{[]byte("0\x191\x170\x15\x06\x03U\x04\x03\x13\x0ESmallstep CA 1"), []byte("0\x191\x170\x15\x06\x03U\x04\x03\x13\x0ESmallstep CA 2")}, false},
		{"ok files", args{"testdata/capath2/root1.crt,testdata/capath2/root2.crt"}, [][]byte{[]byte("0\x191\x170\x15\x06\x03U\x04\x03\x13\x0ESmallstep CA 1"), []byte("0\x191\x170\x15\x06\x03U\x04\x03\x13\x0ESmallstep CA 2")}, false},
		{"no certs", args{"testdata/secrets"}, nil, true},
		{"missing", args{"testdata/missing.pem"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadCertPool(tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadCertPool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != nil {
				subjects := got.Subjects()
				if !reflect.DeepEqual(subjects, tt.wantSubjects) {
					t.Errorf("x509.CertPool.Subjects() got = %v, want %v", subjects, tt.wantSubjects)
				}
			}
		})
	}
}
