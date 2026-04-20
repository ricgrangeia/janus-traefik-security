package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/janus-project/janus/internal/infrastructure/firewall"
	"github.com/janus-project/janus/internal/infrastructure/llm"
	"github.com/janus-project/janus/internal/infrastructure/logs"
)

const (
	reviewWindowMins = 30  // analyse last N minutes of post-ban activity
	reviewBuckets    = 6   // sparkline buckets (one per 5 minutes)
	reviewBucketSecs = 300 // 5 minutes per bucket
)

// IPVerdict is the result of one AI behavioural review for a banned IP.
type IPVerdict struct {
	Verdict    string    // "A" | "B" | "C"
	Label      string    // human-readable: "PERSISTENT ATTACKER" | "COOLING DOWN"
	Reasoning  string
	HitCount   int
	ReviewedAt time.Time
}

// verdictDTO is the JSON shape Janus-AI is instructed to return.
type verdictDTO struct {
	Verdict   string `json:"verdict"`
	Reasoning string `json:"reasoning"`
}

// BanReviewWorker periodically asks Janus-AI whether each banned IP should
// remain blocked, be lifted on probation, or have its ban maintained.
// Safe for concurrent use.
type BanReviewWorker struct {
	shield   *firewall.ShieldService
	tailer   *logs.AccessLogTailer
	client   *llm.Client
	interval time.Duration

	mu       sync.RWMutex
	verdicts map[string]IPVerdict // IP → latest verdict
}

// NewBanReviewWorker creates a worker. All arguments are required.
func NewBanReviewWorker(
	shield *firewall.ShieldService,
	tailer *logs.AccessLogTailer,
	client *llm.Client,
	interval time.Duration,
) *BanReviewWorker {
	return &BanReviewWorker{
		shield:   shield,
		tailer:   tailer,
		client:   client,
		interval: interval,
		verdicts: make(map[string]IPVerdict),
	}
}

// Run starts the periodic review loop. Blocks until ctx is cancelled.
func (w *BanReviewWorker) Run(ctx context.Context) {
	slog.Info("ban review worker started", "interval", w.interval)
	tk := time.NewTicker(w.interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("ban review worker stopped")
			return
		case <-tk.C:
			w.reviewAll()
		}
	}
}

// GetVerdict returns the latest AI verdict for a specific IP.
func (w *BanReviewWorker) GetVerdict(ip string) (IPVerdict, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	v, ok := w.verdicts[ip]
	return v, ok
}

func (w *BanReviewWorker) reviewAll() {
	ips := w.shield.ListBlocked()
	if len(ips) == 0 {
		return
	}
	slog.Info("ban review: reviewing banned IPs", "count", len(ips))
	for _, ip := range ips {
		w.reviewOne(ip)
	}
}

func (w *BanReviewWorker) reviewOne(ip string) {
	since := time.Now().UTC().Add(-reviewWindowMins * time.Minute)
	hits := w.tailer.HitsForIP(ip, since)

	userContent := buildReviewContext(ip, hits, reviewWindowMins)
	reply, _, err := w.client.Chat(llm.ReviewSystemPrompt, userContent)
	if err != nil {
		slog.Warn("ban review: LLM call failed", "ip", ip, "err", err)
		return
	}

	clean := strings.TrimSpace(reply)
	clean = strings.TrimPrefix(clean, "```json")
	clean = strings.TrimPrefix(clean, "```")
	clean = strings.TrimSuffix(clean, "```")
	clean = strings.TrimSpace(clean)

	var dto verdictDTO
	if json.Unmarshal([]byte(clean), &dto) != nil {
		slog.Warn("ban review: failed to parse verdict JSON", "ip", ip, "raw", reply)
		return
	}

	v := strings.ToUpper(strings.TrimSpace(dto.Verdict))
	verdict := IPVerdict{
		Verdict:    v,
		Label:      verdictLabel(v),
		Reasoning:  dto.Reasoning,
		HitCount:   len(hits),
		ReviewedAt: time.Now().UTC(),
	}

	w.mu.Lock()
	w.verdicts[ip] = verdict
	w.mu.Unlock()

	slog.Info("ban review: verdict", "ip", ip, "verdict", v, "hits", len(hits), "reasoning", dto.Reasoning)

	// Verdict B → AI says it's safe to lift the ban.
	if v == "B" {
		if err := w.shield.UnblockIP(ip); err != nil {
			slog.Warn("ban review: auto-unblock failed", "ip", ip, "err", err)
			return
		}
		slog.Info("ban review: IP auto-unblocked on AI probation", "ip", ip)
		w.mu.Lock()
		delete(w.verdicts, ip)
		w.mu.Unlock()
	}
}

func verdictLabel(v string) string {
	switch v {
	case "A":
		return "PERSISTENT ATTACKER"
	case "B":
		return "COOLING DOWN"
	case "C":
		return "INCONCLUSIVE"
	default:
		return "REVIEWING"
	}
}

// buildReviewContext assembles the user message sent to the LLM for a single IP review.
func buildReviewContext(ip string, hits []logs.HitRecord, windowMins int) string {
	if len(hits) == 0 {
		return fmt.Sprintf(
			"Banned IP: %s\nReview window: last %d minutes\nActivity: NONE — zero requests detected since the ban.\nFrequency: 0.0 req/min\n",
			ip, windowMins,
		)
	}

	uniquePaths := make(map[string]int, len(hits))
	for _, h := range hits {
		uniquePaths[h.Path]++
	}
	rate := float64(len(hits)) / float64(windowMins)

	type kv struct {
		path  string
		count int
	}
	sorted := make([]kv, 0, len(uniquePaths))
	for p, c := range uniquePaths {
		sorted = append(sorted, kv{p, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})
	if len(sorted) > 5 {
		sorted = sorted[:5]
	}

	var paths strings.Builder
	for _, entry := range sorted {
		fmt.Fprintf(&paths, "  %s  (%d hits)\n", entry.path, entry.count)
	}

	return fmt.Sprintf(
		"Banned IP: %s\nReview window: last %d minutes\nTotal blocked requests: %d\nRequest frequency: %.1f req/min\nUnique paths targeted: %d\nTop targeted paths:\n%s",
		ip, windowMins, len(hits), rate, len(uniquePaths), paths.String(),
	)
}
