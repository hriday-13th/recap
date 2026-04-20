package decodertest

import (
	"net"
	"testing"
	"time"
 
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"recap/internal/decoder"
)

func buildTCPPacket(srcIP, dstIP string, srcPort, dstPort layers.TCPPort, payload []byte, syn, ack bool) gopacket.Packet {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version: 4,
		SrcIP: net.ParseIP(srcIP).To4(),
		DstIP: net.ParseIP(dstIP).To4(),
		Protocol: layers.IPProtocolTCP,
		TTL: 64,
	}
	
	tcp := &layers.TCP {
		SrcPort: srcPort,
		DstPort: dstPort,
		SYN: syn,
		ACK: ack,
	}

	_ = tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	_ = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	pkt.Metadata().Timestamp = time.Now()
	return pkt
}

func TestDecode_TCP(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	pkt := buildTCPPacket("192.168.1.1", "93.184.216.34", 54321, 80, payload, false, true)
 
	decoded, ok := decoder.Decode(pkt)
	if !ok {
		t.Fatal("expected Decoded to succeed, but got failure")
	}

	if decoded.Protocol != "TCP" {
		t.Errorf("protocol: got %q, want %q", decoded.Protocol, "TCP")
	}
	if decoded.SrcPort != 54321 {
		t.Errorf("src port: got %d, want 54321", decoded.SrcPort)
	}
	if decoded.DstPort != 80 {
		t.Errorf("dst port: got %d, want 80", decoded.DstPort)
	}
	if !decoded.TCPFlags.ACK {
		t.Error("expected ACK flag to be set")
	}
	if decoded.TCPFlags.SYN {
		t.Error("expected SYN flag to be unset")
	}
	if string(decoded.Payload) != string(payload) {
		t.Errorf("payload mismatch: got %q, want %q", decoded.Payload, payload)
	}
}

func TestDecode_SYN(t *testing.T) {
	pkt := buildTCPPacket("10.0.0.1", "10.0.0.2", 12345, 443, nil, true, false)
	decoded, ok := decoder.Decode(pkt)
	if !ok {
		t.Fatal("expected Decode to succeed")
	}
	if !decoded.TCPFlags.SYN {
		t.Error("expected SYN flag")
	}
	if decoded.Payload != nil {
		t.Error("expected nil payload for SYN")
	}
	if !decoded.IsHTTPS() {
		t.Error("expected IsHTTPS() to be true for port 443")
	}
}

func TestDecode_HTTPDetection(t *testing.T) {
	pkt := buildTCPPacket("10.0.0.1", "10.0.0.2", 54000, 80, []byte("GET /"), false, true)
	decoded, _ := decoder.Decode(pkt)
	if !decoded.IsHTTP() {
		t.Error("expected IsHTTP() to be true for port 80")
	}
}