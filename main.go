package recap

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"time"
	"os/signal"
	"github.com/google/gopacket"
	"recap/internal/capturer"
	"recap/internal/decoder"
	"recap/internal/metrics"
	"recap/internal/writer"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Capture: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	iface := flag.String("iface", "", "network interface (default: auto-detect)")
	filter := flag.String("filter", "", `BPF filter expression, e.g. "tcp port 80"`)
	outfile := flag.String("out", "", "write pcap output to file (default: stdout)")
	readfile := flag.String("read", "", "replay a saved pcap file instead of live capture")
	promisc := flag.Bool("promisc", true, "enable promiscous mode")
	verbose := flag.Bool("v", false, "print packet payloads (up to 128 bytes)")
	quiet := flag.Bool("q", false, "suppress per-packet output")
	statsInterval := flag.Duration("stats", 10 * time.Second, "stats logging interval")
	chanBuffer := flag.Int("buffer", 1024, "packet channel buffer depth")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var (
		cap *capturer.Capturer
		err error
	)

	if *readfile != "" {
		cap, err = capturer.NewFromFile(*readfile, *filter, logger)
	} else {
		cap, err = capturer.New(capturer.Config{
			Interface: *iface,
			BPFFilter: *filter,
			Promiscuous: *promisc,
		}, logger)
	}
	if err != nil {
		return fmt.Errorf("init capture: %w", err)
	}

	logger.Info("link type", "type", cap.LinkType())

	// PCAP writer
	var pcapWriter *writer.PcapWriter
	if *outfile != "" {
		pcapWriter, err = writer.NewPcapWriter(*outfile, capturer.DefaultSnapLen, 1)
	}
	if err != nil {
		return fmt.Errorf("init pcap writer: %w", err)
	}

	printer := writer.NewTextPrinter(os.Stdout, *verbose)

	stats := &metrics.Counters{}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	stats.RunLogger(ctx, logger, *statsInterval)

	rawCh := make(chan gopacket.Packet, *chanBuffer)

	capErr := make(chan error, 1)
	go func() {
		capErr <- cap.Run(ctx, rawCh)
	}()

	logger.Info("capture started - press Ctrl+C to stop")

	for {
		select {
		case pkt, ok := <- rawCh:
			if !ok {
				logger.Info("all packets processed")
				stats.Log(logger)
				return nil
			}
			if pcapWriter != nil {
				if writeErr := pcapWriter.WritePacket(pkt); writeErr != nil {
					logger.Warn("pcap write error", "err", writeErr)
					stats.AddError()
				}
			}
			decoded, ok := decoder.Decode(pkt)
			if !ok {
				stats.AddRaw()
				continue
			}
			stats.Add(decoded.NetworkLen)

			if !*quiet {
				printer.Print(decoded)
			}

		case err := <- capErr:
			if err != nil {
				return fmt.Errorf("pture error: %w", err)
			}
			for {
				select {
				case pkt := <- rawCh:
					if pcapWriter != nil {
						_ = pcapWriter.WritePacket(pkt)
					}
					if d, ok := decoder.Decode(pkt); ok {
						stats.Add(d.NetworkLen)
						if !*quiet {
							printer.Print(d)
						}
					}
				default:
					stats.Log(logger)
					return nil
				}
			}

		case <- ctx.Done():
			logger.Info("signal received, draining packets...")
			for {
				select {
				case pkt := <- rawCh:
					if pcapWriter != nil {
						_ = pcapWriter.WritePacket(pkt)
					}
					if d, ok := decoder.Decode(pkt); ok {
						stats.Add(d.NetworkLen)
					}
				default:
					stats.Log(logger)
					return nil
				}
			}
		}
	}
}