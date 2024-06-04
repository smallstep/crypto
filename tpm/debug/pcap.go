package debug

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type pcapTap struct {
	in  *pcapWriter
	out *pcapWriter
}

func (t *pcapTap) Rx() io.Writer {
	return t.in
}

func (t *pcapTap) Tx() io.Writer {
	return t.out
}

func NewPcapTap(w io.Writer) (Tap, error) {
	pw := pcapgo.NewWriter(w)
	return &pcapTap{
		in: &pcapWriter{
			in:     true,
			writer: pw,
		},
		out: &pcapWriter{
			writer: pw,
		},
	}, nil
}

type pcapWriter struct {
	in     bool
	writer *pcapgo.Writer
}

var (
	outSeq uint32
	inSeq  uint32
	mu     sync.Mutex
)

func (w *pcapWriter) Write(data []byte) (int, error) {
	mu.Lock()
	defer mu.Unlock()

	err := write(w.writer, data, w.in, inSeq, outSeq)

	if w.in {
		inSeq += uint32(len(data))
	} else {
		outSeq += uint32(len(data))
	}

	return len(data), err
}

var ethernetLayer = &layers.Ethernet{
	SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	EthernetType: layers.EthernetTypeIPv4,
}

var ipLayer = &layers.IPv4{
	Version:  4,
	TTL:      64,
	Flags:    layers.IPv4DontFragment,
	Protocol: layers.IPProtocolTCP,
	SrcIP:    net.IP{127, 0, 0, 1},
	DstIP:    net.IP{127, 0, 0, 1},
}

var serializeOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

var decodeOptions = gopacket.DecodeOptions{
	Lazy:   true,
	NoCopy: true,
}

const snapLen = uint32(65536)

var once sync.Once
var errHeaderWrite error

func write(w *pcapgo.Writer, data []byte, in bool, inSeq, outSeq uint32) error {
	var tcpLayer = &layers.TCP{Window: 16}
	if in {
		tcpLayer.SrcPort = layers.TCPPort(2321)
		tcpLayer.DstPort = layers.TCPPort(50001)
		tcpLayer.ACK = true
		tcpLayer.Seq = inSeq
		tcpLayer.Ack = outSeq
		tcpLayer.PSH = true
	} else {
		tcpLayer.SrcPort = layers.TCPPort(50001)
		tcpLayer.DstPort = layers.TCPPort(2321)
		tcpLayer.ACK = false
		tcpLayer.Seq = outSeq
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, serializeOptions,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(data),
	); err != nil {
		return fmt.Errorf("failed serializing layers: %w", err)
	}

	p := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, decodeOptions)

	once.Do(func() {
		// TODO: do once on the very first write to the output; if it's a file, check there's no pcap header yet
		if err := w.WriteFileHeader(snapLen, layers.LinkTypeEthernet); err != nil {
			errHeaderWrite = err
		}
	})
	if errHeaderWrite != nil {
		return fmt.Errorf("failed writing pcap header: %w", errHeaderWrite)
	}

	ci := p.Metadata().CaptureInfo
	ci.CaptureLength = len(p.Data())
	ci.Length = ci.CaptureLength
	ci.Timestamp = time.Now()

	if err := w.WritePacket(ci, p.Data()); err != nil {
		return fmt.Errorf("failed writing packet data: %w", err)
	}

	return nil
}
