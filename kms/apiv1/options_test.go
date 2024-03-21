package apiv1

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

type fakeKM struct{}

func (f *fakeKM) GetPublicKey(req *GetPublicKeyRequest) (crypto.PublicKey, error) {
	return nil, NotImplementedError{}
}
func (f *fakeKM) CreateKey(req *CreateKeyRequest) (*CreateKeyResponse, error) {
	return nil, NotImplementedError{}
}
func (f *fakeKM) CreateSigner(req *CreateSignerRequest) (crypto.Signer, error) {
	return nil, NotImplementedError{}
}
func (f *fakeKM) Close() error { return NotImplementedError{} }

func TestMain(m *testing.M) {
	Register(Type("fake"), func(ctx context.Context, opts Options) (KeyManager, error) {
		return &fakeKM{}, nil
	})
	os.Exit(m.Run())
}

func TestOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		options *Options
		wantErr bool
	}{
		{"nil", nil, false},
		{"softkms", &Options{Type: "softkms"}, false},
		{"cloudkms", &Options{Type: "cloudkms"}, false},
		{"awskms", &Options{Type: "awskms"}, false},
		{"sshagentkms", &Options{Type: "sshagentkms"}, false},
		{"pkcs11", &Options{Type: "pkcs11"}, false},
		{"unsupported", &Options{Type: "unsupported"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.options.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Options.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOptions_GetType(t *testing.T) {
	type fields struct {
		Type Type
		URI  string
	}
	tests := []struct {
		name    string
		fields  fields
		want    Type
		wantErr bool
	}{
		{"ok", fields{PKCS11, ""}, PKCS11, false},
		{"ok default", fields{"", ""}, SoftKMS, false},
		{"ok by uri", fields{"", "PKCS11:foo=bar"}, PKCS11, false},
		{"ok by uri", fields{"", "softkms:foo=bar"}, SoftKMS, false},
		{"ok by uri", fields{"", "cloudkms:foo=bar"}, CloudKMS, false},
		{"ok by uri", fields{"", "awskms:foo=bar"}, AmazonKMS, false},
		{"ok by uri", fields{"", "pkcs11:foo=bar"}, PKCS11, false},
		{"ok by uri", fields{"", "yubikey:foo=bar"}, YubiKey, false},
		{"ok by uri", fields{"", "sshagentkms:foo=bar"}, SSHAgentKMS, false},
		{"ok by uri", fields{"", "azurekms:foo=bar"}, AzureKMS, false},
		{"fail uri", fields{"", "foo=bar"}, DefaultKMS, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Options{
				Type: tt.fields.Type,
				URI:  tt.fields.URI,
			}
			got, err := o.GetType()
			if (err != nil) != tt.wantErr {
				t.Errorf("Options.GetType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Options.GetType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrNotImplemented_Error(t *testing.T) {
	type fields struct {
		msg string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"default", fields{}, "not implemented"},
		{"custom", fields{"custom message: not implemented"}, "custom message: not implemented"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NotImplementedError{
				Message: tt.fields.msg,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("ErrNotImplemented.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrAlreadyExists_Error(t *testing.T) {
	type fields struct {
		msg string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"default", fields{}, "already exists"},
		{"custom", fields{"custom message: key already exists"}, "custom message: key already exists"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := AlreadyExistsError{
				Message: tt.fields.msg,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("ErrAlreadyExists.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNotFoundError_Error(t *testing.T) {
	type fields struct {
		msg string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{"default", fields{}, "not found"},
		{"custom", fields{"custom message: not found"}, "custom message: not found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NotFoundError{
				Message: tt.fields.msg,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("ErrAlreadyExists.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTypeOf(t *testing.T) {
	type args struct {
		rawuri string
	}
	tests := []struct {
		name    string
		args    args
		want    Type
		wantErr bool
	}{
		{"ok softkms", args{"softkms:foo=bar"}, SoftKMS, false},
		{"ok cloudkms", args{"CLOUDKMS:"}, CloudKMS, false},
		{"ok amazonkms", args{"awskms:foo=bar"}, AmazonKMS, false},
		{"ok pkcs11", args{"PKCS11:foo=bar"}, PKCS11, false},
		{"ok yubikey", args{"yubikey:foo=bar"}, YubiKey, false},
		{"ok sshagentkms", args{"sshagentkms:"}, SSHAgentKMS, false},
		{"ok azurekms", args{"azurekms:foo=bar"}, AzureKMS, false},
		{"ok capi", args{"CAPI:foo-bar"}, CAPIKMS, false},
		{"ok tpmkms", args{"tpmkms:"}, TPMKMS, false},
		{"ok registered", args{"FAKE:"}, Type("fake"), false},
		{"fail empty", args{""}, DefaultKMS, true},
		{"fail parse", args{"softkms"}, DefaultKMS, true},
		{"fail kms", args{"foobar:foo=bar"}, DefaultKMS, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TypeOf(tt.args.rawuri)
			if (err != nil) != tt.wantErr {
				t.Errorf("TypeOf() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("TypeOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestError_Is(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{"ok not implemented", NotImplementedError{}, NotImplementedError{}, true},
		{"ok not implemented with message", NotImplementedError{Message: "something"}, NotImplementedError{}, true},
		{"ok already exists", AlreadyExistsError{}, AlreadyExistsError{}, true},
		{"ok already exists with message", AlreadyExistsError{Message: "something"}, AlreadyExistsError{}, true},
		{"ok not found", NotFoundError{}, NotFoundError{}, true},
		{"ok not found with message", NotFoundError{Message: "something"}, NotFoundError{}, true},
		{"fail not implemented", errors.New("not implemented"), NotImplementedError{}, false},
		{"fail already exists", errors.New("already exists"), AlreadyExistsError{}, false},
		{"fail not found", errors.New("not found"), NotFoundError{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, errors.Is(tt.err, tt.target))
			assert.Equal(t, tt.want, errors.Is(fmt.Errorf("wrap 1: %w", tt.err), tt.target))
			assert.Equal(t, tt.want, errors.Is(fmt.Errorf("wrap 1: %w", fmt.Errorf("wrap 2: %w", tt.err)), tt.target))
		})
	}
}
