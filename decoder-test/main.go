package decodertest

import (
	"net"
	"testing"
	"time"
 
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func buildTCPPacket(srcIP, dstIP string, srcPort, dstPort layers.TCPPort, payload []byte, syn, ack bool) gopacket.Packet {
	
}