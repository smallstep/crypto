package tlsutil

import (
	"testing"
)

func TestSanitizeName(t *testing.T) {
	type args struct {
		domain string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok", args{"smallstep.com"}, "smallstep.com", false},
		{"ok ascii", args{"bücher.example.com"}, "xn--bcher-kva.example.com", false},
		{"fail", args{"xn--bücher.example.com"}, "", true},
		{"fail empty", args{""}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeName(tt.args.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("SanitizeName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SanitizeName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeHost(t *testing.T) {
	type args struct {
		host string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"ok", args{"smallstep.com"}, "smallstep.com", false},
		{"ok port", args{"smallstep.com:443"}, "smallstep.com", false},
		{"ok ascii", args{"bücher.example.com"}, "xn--bcher-kva.example.com", false},
		{"ok ascii port", args{"bücher.example.com:443"}, "xn--bcher-kva.example.com", false},
		{"fail", args{"xn--bücher.example.com"}, "", true},
		{"fail port", args{"xn--bücher.example.com:443"}, "", true},
		{"fail empty", args{""}, "", true},
		{"fail empty with port", args{":443"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SanitizeHost(tt.args.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("SanitizeHost() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SanitizeHost() = %v, want %v", got, tt.want)
			}
		})
	}
}
