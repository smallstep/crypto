package debug

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_PcapTapWrites(t *testing.T) {
	var buf bytes.Buffer
	tr, err := NewPcapTap(&buf)
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

	r, err := pcapgo.NewReader(&buf)
	require.NoError(t, err)

	count := 0
	packetSource := gopacket.NewPacketSource(r, r.LinkType())
	for packet := range packetSource.Packets() {
		t.Log(packet.Dump())
		count += 1
	}

	require.Equal(t, 4, count) // 4 packets expected
}
