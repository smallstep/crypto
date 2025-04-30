package uri

import (
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParse(t *testing.T, s string) *URI {
	t.Helper()
	u, err := Parse(s)
	require.NoError(t, err)
	return u
}

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

func TestURI_Has(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want bool
	}{
		{"ok", mustParse(t, "yubikey:slot-id=9a"), args{"slot-id"}, true},
		{"ok empty", mustParse(t, "yubikey:slot-id="), args{"slot-id"}, true},
		{"ok query", mustParse(t, "yubikey:pin=123456?slot-id="), args{"slot-id"}, true},
		{"ok empty no equal", mustParse(t, "yubikey:slot-id"), args{"slot-id"}, true},
		{"ok query no equal", mustParse(t, "yubikey:pin=123456?slot-id"), args{"slot-id"}, true},
		{"ok empty no equal other", mustParse(t, "yubikey:slot-id;pin=123456"), args{"slot-id"}, true},
		{"ok query no equal other", mustParse(t, "yubikey:pin=123456?slot-id&pin=123456"), args{"slot-id"}, true},
		{"fail", mustParse(t, "yubikey:pin=123456"), args{"slot-id"}, false},
		{"fail with query", mustParse(t, "yubikey:pin=123456?slot=9a"), args{"slot-id"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.uri.Has(tt.args.key); got != tt.want {
				t.Errorf("URI.Has() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestURI_Get(t *testing.T) {
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want string
	}{
		{"ok", mustParse(t, "yubikey:slot-id=9a"), args{"slot-id"}, "9a"},
		{"ok first", mustParse(t, "yubikey:slot-id=9a;slot-id=9b"), args{"slot-id"}, "9a"},
		{"ok multiple", mustParse(t, "yubikey:slot-id=9a;foo=bar"), args{"foo"}, "bar"},
		{"ok in query", mustParse(t, "yubikey:slot-id=9a?foo=bar"), args{"foo"}, "bar"},
		{"fail missing", mustParse(t, "yubikey:slot-id=9a"), args{"foo"}, ""},
		{"fail missing query", mustParse(t, "yubikey:slot-id=9a?bar=zar"), args{"foo"}, ""},
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
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want bool
	}{
		{"true", mustParse(t, "azurekms:name=foo;vault=bar;hsm=true"), args{"hsm"}, true},
		{"TRUE", mustParse(t, "azurekms:name=foo;vault=bar;hsm=TRUE"), args{"hsm"}, true},
		{"tRUe query", mustParse(t, "azurekms:name=foo;vault=bar?hsm=tRUe"), args{"hsm"}, true},
		{"false", mustParse(t, "azurekms:name=foo;vault=bar;hsm=false"), args{"hsm"}, false},
		{"false query", mustParse(t, "azurekms:name=foo;vault=bar?hsm=false"), args{"hsm"}, false},
		{"empty", mustParse(t, "azurekms:name=foo;vault=bar;hsm=?bar=true"), args{"hsm"}, false},
		{"missing", mustParse(t, "azurekms:name=foo;vault=bar"), args{"hsm"}, false},
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
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want []byte
	}{
		{"ok", mustParse(t, "yubikey:slot-id=9a"), args{"slot-id"}, []byte{0x9a}},
		{"ok prefix", mustParse(t, "yubikey:slot-id=0x9a"), args{"slot-id"}, []byte{0x9a}},
		{"ok first", mustParse(t, "yubikey:slot-id=9a9b;slot-id=9b"), args{"slot-id"}, []byte{0x9a, 0x9b}},
		{"ok percent", mustParse(t, "yubikey:slot-id=9a;foo=%9a%9b%9c"), args{"foo"}, []byte{0x9a, 0x9b, 0x9c}},
		{"ok in query", mustParse(t, "yubikey:slot-id=9a?foo=9a"), args{"foo"}, []byte{0x9a}},
		{"ok in query percent", mustParse(t, "yubikey:slot-id=9a?foo=%9a"), args{"foo"}, []byte{0x9a}},
		{"ok missing", mustParse(t, "yubikey:slot-id=9a"), args{"foo"}, nil},
		{"ok missing query", mustParse(t, "yubikey:slot-id=9a?bar=zar"), args{"foo"}, nil},
		{"ok no hex", mustParse(t, "yubikey:slot-id=09a?bar=zar"), args{"slot-id"}, []byte{'0', '9', 'a'}},
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
	tests := []struct {
		name string
		uri  *URI
		want string
	}{
		{"from value", mustParse(t, "pkcs11:id=%72%73?pin-value=0123456789"), "0123456789"},
		{"from source", mustParse(t, "pkcs11:id=%72%73?pin-source=testdata/pin.txt"), "trim-this-pin"},
		{"from missing", mustParse(t, "pkcs11:id=%72%73"), ""},
		{"from source missing", mustParse(t, "pkcs11:id=%72%73?pin-source=testdata/foo.txt"), ""},
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
	tests := []struct {
		name string
		uri  *URI
		want string
	}{
		{"ok new", New("yubikey", url.Values{"slot-id": []string{"9a"}, "foo": []string{"bar"}}), "yubikey:foo=bar;slot-id=9a"},
		{"ok newOpaque", NewOpaque("cloudkms", "projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"), "cloudkms:projects/p/locations/l/keyRings/k/cryptoKeys/c/cryptoKeyVersions/1"},
		{"ok newFile", NewFile("/path/to/file.key"), "file:///path/to/file.key"},
		{"ok parse", mustParse(t, "yubikey:slot-id=9a;foo=bar?bar=zar"), "yubikey:foo=bar;slot-id=9a?bar=zar"},
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
	type args struct {
		key string
	}
	tests := []struct {
		name string
		uri  *URI
		args args
		want *int64
	}{
		{"ok", mustParse(t, "tpmkms:renewal-percentage=70"), args{"renewal-percentage"}, &seventy},
		{"ok empty", mustParse(t, "tpmkms:empty"), args{"renewal-percentage"}, nil},
		{"ok non-integer", mustParse(t, "tpmkms:renewal-percentage=not-an-integer"), args{"renewal-percentage"}, nil},
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
	type args struct {
		key string
	}
	tests := []struct {
		name    string
		uri     *URI
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok", mustParse(t, "capi:sha1=9a"), args{"sha1"}, []byte{0x9a}, false},
		{"ok first", mustParse(t, "capi:sha1=9a9b;sha1=9b"), args{"sha1"}, []byte{0x9a, 0x9b}, false},
		{"ok prefix", mustParse(t, "capi:sha1=0x9a9b;sha1=9b"), args{"sha1"}, []byte{0x9a, 0x9b}, false},
		{"ok missing", mustParse(t, "capi:foo=9a"), args{"sha1"}, nil, false},
		{"fail odd hex", mustParse(t, "capi:sha1=09a?bar=zar"), args{"sha1"}, nil, true},
		{"fail invalid hex", mustParse(t, "capi:sha1=9z?bar=zar"), args{"sha1"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.uri.GetHexEncoded(tt.args.key)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				return
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestURI_Read(t *testing.T) {
	// Read does not trim the contents of the file
	expected := []byte("trim-this-pin \n")

	path := filepath.Join(t.TempDir(), "management.key")
	require.NoError(t, os.WriteFile(path, expected, 0600))
	managementKeyURI := &url.URL{
		Scheme: "file",
		Path:   path,
	}
	pathURI := &URI{
		URL: &url.URL{Scheme: "yubikey"},
		Values: url.Values{
			"management-key-source": []string{managementKeyURI.String()},
		},
	}

	type args struct {
		key string
	}
	tests := []struct {
		name      string
		uri       *URI
		args      args
		want      []byte
		assertion assert.ErrorAssertionFunc
	}{
		{"from attribute", mustParse(t, "yubikey:management-key-source=testdata/pin.txt"), args{"management-key-source"}, expected, assert.NoError},
		{"from query attribute", mustParse(t, "yubikey:?management-key-source=testdata/pin.txt"), args{"management-key-source"}, expected, assert.NoError},
		{"from uri path", pathURI, args{"management-key-source"}, expected, assert.NoError},
		{"from uri opaque", mustParse(t, "yubikey:management-key-source=file:testdata/pin.txt"), args{"management-key-source"}, expected, assert.NoError},
		{"from empty attribute", mustParse(t, "yubikey:management-source-key="), args{"management-key-source"}, nil, assert.NoError},
		{"from missing attribute", mustParse(t, "yubikey:slot-id=82"), args{"management-key-source"}, nil, assert.NoError},
		{"from missing file", mustParse(t, "yubikey:management-key-source=testdata/foo.txt"), args{"management-key-source"}, nil, assert.Error},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.uri.Read(tt.args.key)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
