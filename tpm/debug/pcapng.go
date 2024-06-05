package debug

import (
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var ngSectionInfo = pcapgo.NgSectionInfo{
	Application: "com.smallstep.crypto.tpmtap",
	Hardware:    runtime.GOARCH,
	OS:          runtime.GOOS,
}

var ngInterface = pcapgo.NgInterface{
	Name:                "tpm",
	Description:         "TPM Command Channel",
	OS:                  runtime.GOOS,
	SnapLength:          0, //unlimited
	TimestampResolution: 9,
}

// FlushFunc is the type of function returned when creating
// a new PcapNG tap. The underlying PcapNG writer must be flushed
// before the [io.Writer] it's writing to is closed.
type FlushFunc func() error

// NewPcapngTap creates a new TPM tap that writes the
// the outgoing and incoming TPM communication to the
// provided [io.Writer] in PcapNG format.
func NewPcapngTap(w io.Writer) (Tap, FlushFunc, error) {
	// record current defaults, so that they can be restored after
	// creating a PcapNG writer.
	currentSectionInfo := pcapgo.DefaultNgWriterOptions.SectionInfo
	defer func() {
		pcapgo.DefaultNgWriterOptions.SectionInfo = currentSectionInfo
	}()
	currentInterface := pcapgo.DefaultNgInterface
	defer func() {
		pcapgo.DefaultNgInterface = currentInterface
	}()

	// override some default properties of the PcapNG writer
	pcapgo.DefaultNgWriterOptions.SectionInfo = ngSectionInfo
	pcapgo.DefaultNgInterface = ngInterface

	// create a new PcapNG writer
	pw, err := pcapgo.NewNgWriter(w, layers.LinkTypeEthernet)
	if err != nil {
		return nil, nil, fmt.Errorf("failed creating PcapNG writer: %w", err)
	}
	finish := func() error {
		if err := pw.Flush(); err != nil {
			return fmt.Errorf("failed to flush PcapNG writer: %w", err)
		}
		return nil
	}

	// the single PcapNG writer is used for both TPM commands and responses.
	// It's wrapped, so that the direction of the data is know at the time of
	// writing a new packet to the PcapNG writer.
	return &pcapTap{
		in: &pcapWriter{
			in:     true,
			writer: pw,
		},
		out: &pcapWriter{
			writer: pw,
		},
	}, finish, nil
}

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

type pcapWriter struct {
	in     bool
	writer *pcapgo.NgWriter
}

var (
	outSeq uint32
	inSeq  uint32
	mu     sync.Mutex
)

// Write implements [io.Writer] and writes the provided data
// to the underlying [io.Writer] in PcapNG  format.
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

func write(w *pcapgo.NgWriter, data []byte, in bool, inSeq, outSeq uint32) error {
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

	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		return fmt.Errorf("failed setting network layer: %w", err)
	}
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

	// construct the capture info based on what's in the new packet
	ci := p.Metadata().CaptureInfo
	ci.CaptureLength = len(p.Data())
	ci.Length = ci.CaptureLength
	ci.Timestamp = time.Now()

	if err := w.WritePacket(ci, p.Data()); err != nil {
		return fmt.Errorf("failed writing packet data: %w", err)
	}

	return nil
}
