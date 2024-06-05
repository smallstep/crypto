package debug

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_pcapNGTapWrites(t *testing.T) {
	var buf bytes.Buffer
	tr, flush, err := NewPcapngTap(&buf)
	require.NoError(t, err)

	b, err := hex.DecodeString("8001000000160000017a000000060000010600000001")
	require.NoError(t, err)
	n, err := tr.Tx().Write(b)
	require.NoError(t, err)

	assert.Equal(t, 22, n)

	b, err = hex.DecodeString("80010000001b000000000100000006000000010000010678434720")
	require.NoError(t, err)
	n, err = tr.Rx().Write(b)
	require.NoError(t, err)
	assert.Equal(t, 27, n)

	b, err = hex.DecodeString("8001000000160000017a000000060000010700000001")
	require.NoError(t, err)
	n, err = tr.Tx().Write(b)
	require.NoError(t, err)
	assert.Equal(t, 22, n)

	b, err = hex.DecodeString("80010000001b00000000010000000600000001000001076654504d")
	require.NoError(t, err)
	n, err = tr.Rx().Write(b)
	require.NoError(t, err)
	assert.Equal(t, 27, n)

	// finish writing to the PcapNG tap
	flush()

	r, err := pcapgo.NewNgReader(&buf, pcapgo.DefaultNgReaderOptions)
	require.NoError(t, err)

	info := r.SectionInfo()
	assert.Equal(t, "com.smallstep.crypto.tpmtap", info.Application)

	iface, err := r.Interface(0)
	require.NoError(t, err)
	assert.Equal(t, "tpm", iface.Name)
	assert.Equal(t, "TPM Command Channel", iface.Description)

	count := 0
	packetSource := gopacket.NewZeroCopyPacketSource(r, r.LinkType())
	for p := range packetSource.Packets() {
		t.Log(p.Dump())

		if assert.IsType(t, &layers.TCP{}, p.TransportLayer().(*layers.TCP)) {
			tcp := p.TransportLayer().(*layers.TCP)
			tcp.SetNetworkLayerForChecksum(p.NetworkLayer())

			err, errs := p.VerifyChecksums()
			assert.NoError(t, err)
			assert.Empty(t, errs)
		}
		count += 1
	}

	require.Equal(t, 4, count) // 4 packets expected
}
