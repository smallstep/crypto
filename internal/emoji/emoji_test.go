package emoji

import "testing"

func TestEmoji(t *testing.T) {
	type args struct {
		input []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"ok", args{[]byte{0x00, 0x10, 0x50, 0xAA, 0xFF}}, "👍🛁🇫🇷👛💤"},
		{"empty", args{[]byte{}}, ""},
		{"nil", args{nil}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Emoji(tt.args.input); got != tt.want {
				t.Errorf("Emoji() = %v, want %v", got, tt.want)
			}
		})
	}
}
