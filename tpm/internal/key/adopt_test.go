package key

import (
	"testing"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/stretchr/testify/require"
)

func TestCheckAdoptable(t *testing.T) {
	created := adoptableAttributes | tpm2.FlagUserWithAuth
	for _, tc := range []struct {
		name    string
		attrs   tpm2.KeyProp
		wantErr bool
	}{
		{"a key as Create makes it", created, false},
		{"a restricted key, such as an AK", created | tpm2.FlagRestricted, true},
		{"a key that can leave the TPM", created &^ tpm2.FlagFixedTPM, true},
		{"a key that can move to another parent", created &^ tpm2.FlagFixedParent, true},
		{"a key imported rather than generated", created &^ tpm2.FlagSensitiveDataOrigin, true},
		{"a key that cannot sign", created &^ tpm2.FlagSign, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAdoptable(tpm2.Public{Type: tpm2.AlgECC, Attributes: tc.attrs})
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
