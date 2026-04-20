package metrics

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

type Counters struct {
	Captured 		atomic.Uint64
	Decoded 		atomic.Uint64
	Dropped 		atomic.Uint64
	Errors  		atomic.Uint64
	Bytes   		atomic.Uint64
}

func (c *Counters) Add(bytelen int) {
	c.Captured.Add(1)
	c.Decoded.Add(1)
	c.Bytes.Add(uint64(bytelen))
}

func (c *Counters) AddRaw() {
	c.Captured.Add(1)
}

func (c *Counters) AddDropped() {
	c.Dropped.Add(1)
}

func (c *Counters) AddError() {
	c.Errors.Add(1)
}

func (c *Counters) Log(logger *slog.Logger) {
	logger.Info(
		"capture stats",
		"captured", c.Captured.Load(),
		"decoded", c.Decoded.Load(),
		"dropped", c.Dropped.Load(),
		"errors", c.Errors.Load(),
		"bytes", c.Bytes.Load(),
	)
}

func (c *Counters) RunLogger(ctx context.Context, logger *slog.Logger, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()

		for {
			select {
			case <- ctx.Done():
				c.Log(logger)
				return
			case <- t.C:
				c.Log(logger)
			}
		}
	}()
}