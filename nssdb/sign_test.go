package nssdb

import (
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeySignatureID(t *testing.T) {
	tests := map[uint32]string{
		5:         "sig_key_00000005_00000011",
		676985114: "sig_key_2859f91a_00000011",
	}
	for objectID, metaDataID := range tests {
		t.Run(strconv.Itoa(int(objectID)), func(t *testing.T) {
			got := keySignatureID(objectID)
			assert.Equal(t, metaDataID, got)
		})
	}
}

func TestSign(t *testing.T) {
	globalSalt, err := hex.DecodeString("629bd383b3f9c0cfd0842f994acca3a9c638bfcb")
	require.NoError(t, err)
	passKey := intermediateKey(nil, globalSalt)

	salt, err := hex.DecodeString("03070DAD39B0D0006FEC59632040D2D56DF1625BC2E92D30B233DD239CCC1901")
	require.NoError(t, err)
	// just the 32 bytes of private key material is what gets signed
	val, err := hex.DecodeString("d692a48a8e5eeb6ca34eaa53144506228eee4da5fdf3402c80794e409690e78b")
	require.NoError(t, err)

	want, err := hex.DecodeString("308180305c06092a864886f70d01050e304f304106092a864886f70d01050c3034042003070dad39b0d0006fec59632040d2d56df1625bc2e92d30b233dd239ccc1901020101020120300a06082a864886f70d0209300a06082a864886f70d02090420f9e1dccbf806dd00c6c450c11da24fb21ef220dc1d153764473d1e10ee93bd2c")
	require.NoError(t, err)

	pbkdf2, err := newPBKDF2(true)
	require.NoError(t, err)
	pbkdf2.Salt = salt

	sig, err := pbkdf2.signature(val, passKey)
	require.NoError(t, err)

	pbmac1 := &pbmac1Params{
		kdf: pbkdf2,
		mac: hmacSHA256OID,
	}
	got, err := encodeSignature(sig, pbmac1)
	require.NoError(t, err)

	assert.Equal(t, want, got)
}
