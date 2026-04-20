package decoder

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Packet struct {
	Timestamp		time.Time
	SrcIP			net.IP
	DstIP			net.IP
	Protocol		string
	SrcPort			uint16
	DstPort			uint16
	TCPFlags		TCPFlags
	Payload			[]byte
	NetworkLen		int
	TransportLen	int
}

type TCPFlags struct {
	SYN bool
	ACK bool
	FIN bool
	RST bool
	PSH bool
	URG bool
}

func Decode(pkt gopacket.Packet) (*Packet, bool) {
	out := &Packet{
		Timestamp: pkt.Metadata().Timestamp,
		NetworkLen: pkt.Metadata().Length,
	}

	if n1 := pkt.NetworkLayer(); n1 != nil {
		switch ip := n1.(type) {
		case *layers.IPv4:
			out.SrcIP = copyIP(ip.SrcIP)
			out.DstIP = copyIP(ip.DstIP)
		case *layers.IPv6:
			out.SrcIP = copyIP(ip.SrcIP)
			out.DstIP = copyIP(ip.DstIP)
		}
	}

	if t1 := pkt.TransportLayer(); t1 != nil {
		switch t := t1.(type) {
		case *layers.TCP:
			out.Protocol = "TCP"
			out.SrcPort = uint16(t.SrcPort)
			out.DstPort = uint16(t.DstPort)
			out.TCPFlags = TCPFlags{
				SYN: t.SYN,
				ACK: t.ACK,
				FIN: t.FIN,
				RST: t.RST,
				PSH: t.PSH,
				URG: t.URG,
			}
			payload := t.Payload
			out.TransportLen = len(payload)
			if len(payload) > 0 {
				out.Payload = copyBytes(payload)
			}

		case *layers.UDP:
			out.Protocol = "UDP"
			out.SrcPort = uint16(t.SrcPort)
			out.DstPort = uint16(t.DstPort)
			payload := t.Payload
			if len(payload) > 0 {
				out.Payload = copyBytes(payload)
			}
		}
	} else if a1 := pkt.ApplicationLayer(); a1 != nil {
		payload := a1.Payload()
		if len(payload) > 0 {
			out.Payload = copyBytes(payload)
		}
	}

	if n1 := pkt.NetworkLayer(); n1 != nil {
		return nil, false
	}

	return out, true
}

func (p *Packet) IsHTTP() bool {
	return p.DstPort == 80 || p.SrcPort == 80 ||
		p.DstPort == 8080 || p.SrcPort == 8080
}

func (p *Packet) IsHTTPS() bool {
	return p.DstPort == 443 || p.SrcPort == 443 ||
		p.DstPort == 8443 || p.SrcPort == 8443
}

func copyIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func copyBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}