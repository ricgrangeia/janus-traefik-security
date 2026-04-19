// Package app contains application-layer use cases that orchestrate domain
// services and infrastructure adapters. It has no HTTP or JSON concerns.
package app

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/janus-project/janus/domain"
	traefikinfra "github.com/janus-project/janus/internal/infrastructure/traefik"
	"github.com/janus-project/janus/internal/pulse"
)

// AIAuditWorker runs the AI enrichment pipeline on a ticker and stores the
// latest AI-enriched AuditReport for the HTTP handler to read.
type AIAuditWorker struct {
	client    *traefikinfra.Client
	auditor   domain.Auditor
	analyst   domain.AIAnalyst
	threshold float64
	interval  time.Duration
	tracePath string

	mu     sync.RWMutex
	latest *domain.AIInsights // nil until first successful AI run
}

// NewAIAuditWorker creates a worker. interval is how often the AI audit runs.
// tracePath is the file path where AI audit traces are written (empty = disabled).
func NewAIAuditWorker(
	client *traefikinfra.Client,
	auditor domain.Auditor,
	analyst domain.AIAnalyst,
	threshold float64,
	interval time.Duration,
	tracePath string,
) *AIAuditWorker {
	return &AIAuditWorker{
		client:    client,
		auditor:   auditor,
		analyst:   analyst,
		threshold: threshold,
		interval:  interval,
		tracePath: tracePath,
	}
}

// LatestInsights returns the most recent AI insights, or nil if the AI audit
// has not yet completed. Thread-safe.
func (w *AIAuditWorker) LatestInsights() *domain.AIInsights {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.latest
}

// Run starts the ticker loop. It blocks until ctx is cancelled.
// Designed to be called in a goroutine: go worker.Run(ctx).
func (w *AIAuditWorker) Run(ctx context.Context) {
	slog.Info("AI audit worker started", "interval", w.interval)

	// Run once immediately, then on every tick.
	w.runOnce()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("AI audit worker stopped")
			return
		case <-ticker.C:
			w.runOnce()
		}
	}
}

// runOnce executes one full AI audit cycle.
func (w *AIAuditWorker) runOnce() {
	start := time.Now()

	if !w.client.Ping() {
		slog.Warn("AI audit skipped — Traefik unreachable")
		return
	}

	raw, err := w.client.FetchRawData()
	if err != nil {
		slog.Error("AI audit: fetch rawdata failed", "err", err)
		return
	}

	overview, _ := w.client.FetchOverview()

	var pulseAlerts []domain.PulseAlert
	if overview != nil && overview.Features.Metrics != "" {
		if metricsText, err := w.client.FetchMetrics(); err == nil {
			pulseAlerts = pulse.Analyze(metricsText, w.threshold)
		}
	}

	snapshot := traefikinfra.ToSnapshot(raw, pulseAlerts, true)
	report := w.auditor.Audit(snapshot)
	report.GeneratedAt = time.Now().UTC()

	enriched, err := w.analyst.Analyze(report, snapshot)
	if err != nil {
		slog.Error("AI audit: analyst failed", "err", err,
			"elapsed_ms", time.Since(start).Milliseconds())
		// Analyst sets a Fallback AIInsights — store it so the UI shows the degraded state.
		if enriched.AIInsights != nil {
			w.mu.Lock()
			w.latest = enriched.AIInsights
			w.mu.Unlock()
		}
		return
	}

	if enriched.AIInsights != nil {
		ai := enriched.AIInsights
		slog.Info("AI audit complete",
			"overall_score", enriched.OverallScore,
			"severity", ai.Severity,
			"prompt_tokens", ai.PromptTokens,
			"completion_tokens", ai.CompletionTokens,
			"latency_ms", ai.LatencyMs,
			"shadow_apis", len(ai.ShadowAPIs),
			"aggressivity_alerts", len(ai.AggressivityAlerts),
		)

		WriteAuditTrace(w.tracePath, enriched)

		w.mu.Lock()
		w.latest = ai
		w.mu.Unlock()
	}
}
