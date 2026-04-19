package capturer

import (
	"context"
	"fmt"
	"log/slog"
	"time"

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