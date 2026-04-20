package capturer

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	DefaultSnapLen = 65535
	DefaultReadTimeout = 10 * time.Millisecond
)

type Config struct {
	Interface 		string
	BPFFilter 		string
	Promiscuous 	bool
	SnapLen 		int32
	ReadTimeout 	time.Duration
}

type Capturer struct {
	cfg 			Config
	handle 			*pcap.Handle
	logger 			*slog.Logger
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.SnapLen == 0 {
		out.SnapLen = DefaultSnapLen
	}
	if out.ReadTimeout == 0 {
		out.ReadTimeout = DefaultReadTimeout
	}
	return out
}

func New(cfg Config, logger *slog.Logger) (*Capturer, error) {
	cfg = cfg.withDefaults()

	if cfg.Interface == "" {
		iface, err := findDefaultInterface()
		if err != nil {
			return nil, fmt.Errorf("capturer: no interface specified and auto-detect failed: %w", err)
		}
		cfg.Interface = iface
		logger.Info("auto-detected interface", "iface", cfg.Interface)
	}

	handle, err := pcap.OpenLive(
		cfg.Interface,
		cfg.SnapLen,
		cfg.Promiscuous,
		cfg.ReadTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("capturer: open live on %q: %w", cfg.Interface, err)
	}

	if cfg.BPFFilter != "" {
		if err := handle.SetBPFFilter(cfg.BPFFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("capturer: set BPF Filter %q: %w", cfg.BPFFilter, err)
		}
		logger.Info("BPF filter set", "filter", cfg.BPFFilter)
	}

	logger.Info("capture handle opened",
		"iface", cfg.Interface,
		"snaplen", cfg.SnapLen,
		"promiscuous", cfg.Promiscuous,
	)

	return &Capturer{cfg: cfg, handle: handle, logger: logger}, nil
}

func NewFromFile(path string, filter string, logger *slog.Logger) (*Capturer, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, fmt.Errorf("capturer: open file %q: %w", path, err)
	}
	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("capturer: set BPF filter %q: %w", filter, err)
		}
	}
	cfg := Config{BPFFilter: filter}
	return &Capturer{cfg: cfg, handle: handle, logger: logger}, nil
}

func (c *Capturer) Run(ctx context.Context, out chan<- gopacket.Packet) error {
	defer c.handle.Close()

	src := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	src.NoCopy = true

	packets := src.Packets()

	for {
		select {
		case <- ctx.Done():
			c.logger.Info("capture shutting down", "reason", ctx.Err())
			return nil

		case pkt, ok := <- packets:
			if !ok {
				c.logger.Info("Packet source exhausted (EOF)")
				return nil
			}
			if pkt.ErrorLayer() != nil {
				c.logger.Info("Packets decode error", "err", pkt.ErrorLayer().Error())
				continue
			}
			select {
			case out <- pkt:
			case <- ctx.Done():
				return nil
			}
		}
	}
}

func (c *Capturer) Stats() (*pcap.Stats, error) {
	return c.handle.Stats()
}

func (c *Capturer) LinkType() string {
	return c.handle.LinkType().String()
}

func findDefaultInterface() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	for _, d := range devs {
		if d.Name == "lo" || d.Name == "lo0" {
			continue
		}
		if len(d.Addresses) > 0 {
			return d.Name, nil
		}
	}
	if len(devs) > 0 {
		return devs[0].Name, nil
	}
	return "", fmt.Errorf("no network interfaces found")
}