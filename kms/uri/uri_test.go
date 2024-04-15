package uri

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	type args struct {
		scheme string
		values url.Values
	}
	tests := []struct {
		name string
		args args
		want *URI
	}{
		{"ok", args{"yubikey", url.Values{"slot-id": []string{"9a"}}}, &URI{
			URL:    &url.URL{Scheme: "yubikey", Opaque: "slot-id=9a"},
			Values: url.Values{"slot-id": []string{"9a"}},
		}},
		{"ok multiple", args{"yubikey", url.Values{"slot-id": []string{"9a"}, "foo": []string{"bar"}}}, &URI{
			URL: &url.URL{Scheme: "yubikey", Opaque: "foo=bar;slot-id=9a"},
			Values: url.Values{
				"slot-id": []string{"9a"},
				"foo":     []string{"bar"},
			},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(tt.args.scheme, tt.args.values); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewFile(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name string
		args args
		want *URI
	}{
		{"ok", args{"/tmp/ca.crt"}, &URI{
			URL:    &url.URL{Scheme: "file", Path: "/tmp/ca.crt"},
			Values: url.Values(nil),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewFile(tt.args.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewOpaque(t *testing.T) {
	type args struct {
		scheme string
		opaque string
	}
	tests := []struct {
		name string
		args args
		want *URI
	}{
		{"ok", args{"softkms", "/path/to/file"}, &URI{
			URL:    &url.URL{Scheme: "softkms", Opaque: "/path/to/file"},
			Values: url.Values(nil),
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewOpaque(tt.args.scheme, tt.args.opaque); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewOpaque() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestHasScheme(t *testing.T) {
	type args struct {
		scheme string
		rawuri string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"ok", args{"yubikey", "yubikey:slot-id=9a"}, true},
		{"ok empty", args{"yubikey", "yubikey:"}, true},
		{"ok letter case", args{"awsKMS", "AWSkms:key-id=abcdefg?foo=bar"}, true},
		{"fail", args{"yubikey", "awskms:key-id=abcdefg"}, false},
		{"fail parse", args{"yubikey", "yubi%key:slot-id=9a"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasScheme(tt.args.scheme, tt.args.rawuri); got != tt.want {
				t.Errorf("HasScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseWithScheme(t *testing.T) {
	type args struct {
		scheme string
		rawuri string
	}
	tests := []struct {
		name    string
		args    args
		want    *URI
		wantErr bool
	}{
		{"ok", args{"yubikey", "yubikey:slot-id=9a"}, &URI{
			URL:    &url.URL{Scheme: "yubikey", Opaque: "slot-id=9a"},
			Values: url.Values{"slot-id": []string{"9a"}},
		}, false},
		{"ok schema", args{"cloudkms", "cloudkms:"}, &URI{
			URL:    &url.URL{Scheme: "cloudkms"},
			Values: url.Values{},
		}, false},
		{"ok file", args{"file", "file:///tmp/ca.cert"}, &URI{
			URL:    &url.URL{Scheme: "file", Path: "/tmp/ca.cert"},
			Values: url.Values{},
		}, false},
		{"fail parse", args{"yubikey", "yubikey"}, nil, true},
		{"fail scheme", args{"yubikey", "awskms:slot-id=9a"}, nil, true},
		{"fail schema", args{"cloudkms", "cloudkms"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseWithScheme(tt.args.scheme, tt.args.rawuri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseWithScheme() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseWithScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_Get(t *testing.T) {
	mustParse := func(s string) *URI {
		u, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want string
	}{
		{"ok", mustParse("yubikey:slot-id=9a"), args{"slot-id"}, "9a"},
		{"ok first", mustParse("yubikey:slot-id=9a;slot-id=9b"), args{"slot-id"}, "9a"},
		{"ok multiple", mustParse("yubikey:slot-id=9a;foo=bar"), args{"foo"}, "bar"},
		{"ok in query", mustParse("yubikey:slot-id=9a?foo=bar"), args{"foo"}, "bar"},
		{"fail missing", mustParse("yubikey:slot-id=9a"), args{"foo"}, ""},
		{"fail missing query", mustParse("yubikey:slot-id=9a?bar=zar"), args{"foo"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.Get(tt.args.key); got != tt.want {
				t.Errorf("URI.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_GetBool(t *testing.T) {
	mustParse := func(s string) *URI {
		u, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want bool
	}{
		{"true", mustParse("azurekms:name=foo;vault=bar;hsm=true"), args{"hsm"}, true},
		{"TRUE", mustParse("azurekms:name=foo;vault=bar;hsm=TRUE"), args{"hsm"}, true},
		{"tRUe query", mustParse("azurekms:name=foo;vault=bar?hsm=tRUe"), args{"hsm"}, true},
		{"false", mustParse("azurekms:name=foo;vault=bar;hsm=false"), args{"hsm"}, false},
		{"false query", mustParse("azurekms:name=foo;vault=bar?hsm=false"), args{"hsm"}, false},
		{"empty", mustParse("azurekms:name=foo;vault=bar;hsm=?bar=true"), args{"hsm"}, false},
		{"missing", mustParse("azurekms:name=foo;vault=bar"), args{"hsm"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.GetBool(tt.args.key); got != tt.want {
				t.Errorf("URI.GetBool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_GetEncoded(t *testing.T) {
	mustParse := func(s string) *URI {
		u, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want []byte
	}{
		{"ok", mustParse("yubikey:slot-id=9a"), args{"slot-id"}, []byte{0x9a}},
		{"ok prefix", mustParse("yubikey:slot-id=0x9a"), args{"slot-id"}, []byte{0x9a}},
		{"ok first", mustParse("yubikey:slot-id=9a9b;slot-id=9b"), args{"slot-id"}, []byte{0x9a, 0x9b}},
		{"ok percent", mustParse("yubikey:slot-id=9a;foo=%9a%9b%9c"), args{"foo"}, []byte{0x9a, 0x9b, 0x9c}},
		{"ok in query", mustParse("yubikey:slot-id=9a?foo=9a"), args{"foo"}, []byte{0x9a}},
		{"ok in query percent", mustParse("yubikey:slot-id=9a?foo=%9a"), args{"foo"}, []byte{0x9a}},
		{"ok missing", mustParse("yubikey:slot-id=9a"), args{"foo"}, nil},
		{"ok missing query", mustParse("yubikey:slot-id=9a?bar=zar"), args{"foo"}, nil},
		{"ok no hex", mustParse("yubikey:slot-id=09a?bar=zar"), args{"slot-id"}, []byte{'0', '9', 'a'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.uri.GetEncoded(tt.args.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("URI.GetEncoded() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_Pin(t *testing.T) {
	mustParse := func(s string) *URI {
		u, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	tests := []struct {
		name string
		uri  *URI
		want string
	}{
		{"from value", mustParse("pkcs11:id=%72%73?pin-value=0123456789"), "0123456789"},
		{"from source", mustParse("pkcs11:id=%72%73?pin-source=testdata/pin.txt"), "trim-this-pin"},
		{"from missing", mustParse("pkcs11:id=%72%73"), ""},
		{"from source missing", mustParse("pkcs11:id=%72%73?pin-source=testdata/foo.txt"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.Pin(); got != tt.want {
				t.Errorf("URI.Pin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_String(t *testing.T) {
	mustParse := func(s string) *URI {
		u, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	tests := []struct {
		name string
		uri  *URI
		want string
	}{
		{"ok new", New("yubikey", url.Values{"slot-id": []string{"9a"}, "foo": []string{"bar"}}), "yubikey:foo=bar;slot-id=9a"},
		{"ok newOpaque", NewOpaque("cloudkms", "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"), "cloudkms:projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"},
		{"ok newFile", NewFile("/path/to/file.key"), "file:///path/to/file.key"},
		{"ok parse", mustParse("yubikey:slot-id=9a;foo=bar?bar=zar"), "yubikey:foo=bar;slot-id=9a?bar=zar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.String(); got != tt.want {
				t.Errorf("URI.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_GetInt(t *testing.T) {
	seventy := int64(70)
	mustParse := func(s string) *URI {
		u, err := Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want *int64
	}{
		{"ok", mustParse("tpmkms:renewal-percentage=70"), args{"renewal-percentage"}, &seventy},
		{"ok empty", mustParse("tpmkms:empty"), args{"renewal-percentage"}, nil},
		{"ok non-integer", mustParse("tpmkms:renewal-percentage=not-an-integer"), args{"renewal-percentage"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.uri.GetInt(tt.args.key)
			if tt.want != nil {
				assert.Equal(t, *tt.want, *got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func TestURI_GetHexEncoded(t *testing.T) {
	mustParse := func(t *testing.T, s string) *URI {
		t.Helper()
		u, err := Parse(s)
		require.NoError(t, err)
		return u
	}
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want []byte
	}{
		{"ok", mustParse(t, "capi:sha1=9a"), args{"sha1"}, []byte{0x9a}},
		{"ok first", mustParse(t, "capi:sha1=9a9b;sha1=9b"), args{"sha1"}, []byte{0x9a, 0x9b}},
		{"ok prefix", mustParse(t, "capi:sha1=0x9a9b;sha1=9b"), args{"sha1"}, []byte{0x9a, 0x9b}},
		{"ok missing", mustParse(t, "capi:foo=9a"), args{"sha1"}, nil},
		{"ok odd hex", mustParse(t, "capi:sha1=09a?bar=zar"), args{"sha1"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.uri.GetHexEncoded(tt.args.key)
			assert.Equal(t, tt.want, got)
		})
	}
}
