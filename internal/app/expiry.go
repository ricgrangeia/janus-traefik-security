package app

import (
	"context"
	"log/slog"
	"time"

	"github.com/janus-project/janus/internal/infrastructure/firewall"
	"github.com/janus-project/janus/internal/infrastructure/telegram"
)

// BlockExpiryWorker periodically purges expired auto-blocks from the Shield
// and (optionally) fires a Telegram IP_UNBLOCKED alert with source=expiry.
type BlockExpiryWorker struct {
	shield   *firewall.ShieldService
	interval time.Duration
	notifier ThreatNotifier // optional
}

// NewBlockExpiryWorker returns a worker that runs every `interval`. Use 1 min
// in production — purge granularity equal to interval means a 30-min block
// effectively expires somewhere in [30, 31] min, which is fine.
func NewBlockExpiryWorker(shield *firewall.ShieldService, interval time.Duration) *BlockExpiryWorker {
	if interval <= 0 {
		interval = time.Minute
	}
	return &BlockExpiryWorker{shield: shield, interval: interval}
}

// WithNotifier attaches a Telegram notifier for IP_UNBLOCKED alerts when a
// block expires naturally.
func (w *BlockExpiryWorker) WithNotifier(n ThreatNotifier) *BlockExpiryWorker {
	w.notifier = n
	return w
}

// Run starts the purge loop. Blocks until ctx is cancelled.
func (w *BlockExpiryWorker) Run(ctx context.Context) {
	slog.Info("block expiry worker started", "interval", w.interval)
	tk := time.NewTicker(w.interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("block expiry worker stopped")
			return
		case <-tk.C:
			w.tick()
		}
	}
}

func (w *BlockExpiryWorker) tick() {
	expired := w.shield.PurgeExpired()
	for _, ip := range expired {
		slog.Info("Shield: IP block expired", "ip", ip)
		if w.notifier != nil && w.notifier.Enabled() {
			_ = w.notifier.SendUnblockAlert(telegram.UnblockAlert{
				IP:     ip,
				Source: "expiry",
				Reason: "block duration elapsed",
			})
		}
	}
}
