package writer

import (
	"fmt"
	"io"
	"os"
	"recap/internal/decoder"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PcapWriter struct {
	mu 	 	sync.Mutex
	w		*pcapgo.Writer
	f		*os.File
	buf		[]byte
}

func NewPcapWriter(path string, snaplen uint32, linktype layers.LinkType) (*PcapWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("pcap writer: create %q: %w", path, err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(snaplen, linktype); err != nil {
		f.Close()
		return nil, fmt.Errorf("pcap writer: write file header: %w", err)
	}
	return &PcapWriter{
		w: w,
		f: f,
	}, nil
}

func (p *PcapWriter) WritePacket(pkt gopacket.Packet) error {
	ci := pkt.Metadata().CaptureInfo
	data := pkt.Data()

	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.w.WritePacket(ci, data); err != nil {
		return fmt.Errorf("pcap writer: write packet: %w", err)
	}
	return nil
}

func (p *PcapWriter) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.f.Close()
}

type TextPrinter struct {
	w 			io.Writer
	mu 			sync.Mutex
	verbose 	bool
}

func NewTextPrinter(w io.Writer, verbose bool) *TextPrinter {
	return &TextPrinter{
		w: w,
		verbose: verbose,
	}
}

func (t *TextPrinter) Print(pkt *decoder.Packet) {
	t.mu.Lock()
	defer t.mu.Unlock()

	ts := pkt.Timestamp.Format(time.RFC3339Nano)
	flags := formatTCPFlags(pkt.TCPFlags)

	fmt.Fprintf(t.w, "%s  %-4s  %-15s:%-5d  →  %-15s:%-5d  len=%-5d",
		ts,
		pkt.Protocol,
		formatIP(pkt.SrcIP), pkt.SrcPort,
		formatIP(pkt.DstIP), pkt.DstPort,
		pkt.NetworkLen,
	)

	if flags != "" {
		fmt.Fprintf(t.w, "  flags=[%s]", flags)
	}

	if t.verbose && len(pkt.Payload) > 0 {
		preview := pkt.Payload
		if len(preview) > 128 {
			preview = preview[:128]
		}
		fmt.Fprintf(t.w, "\n  payload(%d): %q", pkt.TransportLen, preview)
	}

	fmt.Fprintln(t.w)
}

func formatIP(ip interface{ String() string }) string {
	if ip == nil {
		return "<nil>"
	}
	return ip.String()
}

func formatTCPFlags(flags decoder.TCPFlags) string {
	var out []byte
	if flags.SYN { out = append(out, 'S')} 
	if flags.ACK { out = append(out, 'A') }
	if flags.FIN { out = append(out, 'F') }
	if flags.RST { out = append(out, 'R') }
	if flags.PSH { out = append(out, 'P') }
	if flags.URG { out = append(out, 'U') }

	return string(out)
}