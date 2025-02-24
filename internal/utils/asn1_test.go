package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPrintableString(t *testing.T) {
	type args struct {
		s         string
		asterisk  bool
		ampersand bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"empty", args{"", false, false}, true},
		{"a", args{"a", false, false}, true},
		{"spaces and caps", args{"My Leaf", false, false}, true},
		{"default allowed punctuation", args{`(Hi+,-./):=?`, false, false}, true},
		{"asterisk not allowed", args{"*", false, false}, false},
		{"ampersand not allowed", args{"&", false, false}, false},
		{"asterisk allowed", args{"*", true, false}, true},
		{"ampersand allowed", args{"&", false, true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsPrintableString(tt.args.s, tt.args.asterisk, tt.args.ampersand))
		})
	}
}
