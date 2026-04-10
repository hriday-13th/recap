package recap

import (
	"flag"
	"fmt"
	"os"
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
	flag.Parse()
}