// Package app contains application-layer use cases that orchestrate domain
// services and infrastructure adapters. It has no HTTP or JSON concerns.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/janus-project/janus/domain"
	"github.com/janus-project/janus/internal/infrastructure/firewall"
	"github.com/janus-project/janus/internal/infrastructure/storage"
	"github.com/janus-project/janus/internal/infrastructure/telegram"
	traefikinfra "github.com/janus-project/janus/internal/infrastructure/traefik"
	"github.com/janus-project/janus/internal/pulse"
)

// ThreatNotifier is a narrow interface so the worker is not coupled to the
// concrete Telegram implementation.
type ThreatNotifier interface {
	Enabled() bool
	SendThreatAlert(serviceName, classification, reasoning, fix string) error
	SendAutoBlockAlert(a telegram.AutoBlockAlert) error
}

// IPContext is enrichment info an optional IPEnricher can provide about an IP.
// Any field may be zero-valued when unknown.
type IPContext struct {
	CountryCode string
	CountryName string
	City        string
	TopRouter   string
	Hits        int
	Count4xx    int
	Count5xx    int
	ErrorRate   float64
}

// IPEnricher resolves an IP to its enrichment context (geo + traffic).
// When nil, auto-block alerts fall back to the minimal template.
type IPEnricher func(ip string) IPContext

// AIAuditWorker runs the AI enrichment pipeline on a ticker and stores the
// latest AI-enriched AuditReport for the HTTP handler to read.
type AIAuditWorker struct {
	client    *traefikinfra.Client
	auditor   domain.Auditor
	analyst   domain.AIAnalyst
	threshold float64
	interval  time.Duration
	tracePath string

	notifier          ThreatNotifier
	store             storage.Store
	shield            *firewall.ShieldService
	enrichIP          IPEnricher
	threatSeverityMin int // alert when bot_scan AI severity >= this value
	autoBlockMin      int // auto-block when bot_scan severity >= this value (default 10)

	mu     sync.RWMutex
	latest *domain.AIInsights // nil until first successful AI run
}

// NewAIAuditWorker creates a worker. tracePath is the JSONL trace file path
// (empty = disabled). Call WithNotifier and WithStorage to opt into alerting
// and persistence.
func NewAIAuditWorker(
	client *traefikinfra.Client,
	auditor domain.Auditor,
	analyst domain.AIAnalyst,
	threshold float64,
	interval time.Duration,
	tracePath string,
) *AIAuditWorker {
	return &AIAuditWorker{
		client:            client,
		auditor:           auditor,
		analyst:           analyst,
		threshold:         threshold,
		interval:          interval,
		tracePath:         tracePath,
		threatSeverityMin: 8,
		autoBlockMin:      10,
	}
}

// WithNotifier attaches a Telegram notifier. severityMin is the minimum overall
// AI severity (0-10) at which a bot_scan alert is sent.
func (w *AIAuditWorker) WithNotifier(n *telegram.Notifier, severityMin int) *AIAuditWorker {
	w.notifier = n
	if severityMin > 0 {
		w.threatSeverityMin = severityMin
	}
	return w
}

// WithStorage attaches a storage backend for audit persistence.
// Accepts any Store — JSON Repository or SQLiteRepository both qualify.
func (w *AIAuditWorker) WithStorage(s storage.Store) *AIAuditWorker {
	w.store = s
	return w
}

// WithIPEnricher attaches an enrichment callback used to decorate auto-block alerts
// with geo + traffic context.
func (w *AIAuditWorker) WithIPEnricher(fn IPEnricher) *AIAuditWorker {
	w.enrichIP = fn
	return w
}

// WithShield attaches the ShieldService for automatic IP blocking.
// autoBlockMin is the AI severity threshold (0-10) above which a bot_scan
// alert with a known IP triggers an automatic block. Default is 10 (critical only).
func (w *AIAuditWorker) WithShield(s *firewall.ShieldService, autoBlockMin int) *AIAuditWorker {
	w.shield = s
	if autoBlockMin > 0 {
		w.autoBlockMin = autoBlockMin
	}
	return w
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
		if enriched.AIInsights != nil {
			w.mu.Lock()
			w.latest = enriched.AIInsights
			w.mu.Unlock()
		}
		return
	}

	if enriched.AIInsights == nil {
		return
	}

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
	w.saveHistory(enriched)
	w.fireThreatAlerts(ai)

	w.mu.Lock()
	w.latest = ai
	w.mu.Unlock()
}

// saveHistory persists a summary to the configured store.
func (w *AIAuditWorker) saveHistory(report domain.AuditReport) {
	if w.store == nil || report.AIInsights == nil {
		return
	}
	ai := report.AIInsights
	redFlags := 0
	for _, ra := range report.RouterAudits {
		if !ra.Router.IsRedirect && !ra.IsClean() {
			redFlags++
		}
	}
	summary := storage.AuditSummary{
		Timestamp:    ai.GeneratedAt,
		OverallScore: report.OverallScore,
		Severity:     ai.Severity,
		RedFlags:     redFlags,
		ShadowAPIs:   len(ai.ShadowAPIs),
		TokensUsed:   ai.TokensUsed,
		LatencyMs:    ai.LatencyMs,
		Fallback:     ai.Fallback,
	}

	// Use the richer SQLite path when available (stores router-level detail).
	if rich, ok := w.store.(storage.RichStore); ok {
		_, err := rich.SaveAuditWithRouters(summary, ToRouterResults(report))
		if err != nil {
			slog.Warn("SQLite: save audit failed", "err", err)
		}
		// Security Decline alert: current score < avg of previous 3.
		if w.notifier != nil && w.notifier.Enabled() && CheckSecurityDecline(rich, 3) {
			_ = w.notifier.SendThreatAlert(
				"global",
				"SECURITY_DECLINE",
				fmt.Sprintf("Current score %d is below average of last 3 audits", report.OverallScore),
				"Review recently changed router configurations",
			)
		}
	} else {
		w.store.Save(summary)
	}
}

// fireThreatAlerts sends Telegram alerts for bot_scan aggressivity alerts that
// meet the severity threshold.
func (w *AIAuditWorker) fireThreatAlerts(ai *domain.AIInsights) {
	if w.notifier == nil || !w.notifier.Enabled() {
		return
	}
	if ai.Severity < w.threatSeverityMin {
		return
	}

	for _, alert := range ai.AggressivityAlerts {
		if !strings.EqualFold(alert.Assessment, "bot_scan") {
			continue
		}

		// BOT_SCAN preview alert intentionally disabled — only auto-block (IP_BANNED)
		// alerts are sent to Telegram. Re-enable here if a noisier feed is wanted.

		// Auto-block: only when severity is critical AND a suspected IP is known.
		if w.shield != nil && ai.Severity >= w.autoBlockMin && alert.SuspectedIP != "" {
			if err := w.shield.BlockIP(alert.SuspectedIP); err != nil {
				slog.Warn("Shield: auto-block failed", "ip", alert.SuspectedIP, "err", err)
			} else {
				slog.Warn("Shield: IP auto-blocked", "ip", alert.SuspectedIP, "service", alert.ServiceName)
				if w.notifier != nil && w.notifier.Enabled() {
					payload := telegram.AutoBlockAlert{
						IP:          alert.SuspectedIP,
						ServiceName: alert.ServiceName,
						Severity:    ai.Severity,
						Reasoning:   alert.Reasoning,
					}
					if w.enrichIP != nil {
						ctx := w.enrichIP(alert.SuspectedIP)
						payload.CountryCode = ctx.CountryCode
						payload.CountryName = ctx.CountryName
						payload.City = ctx.City
						payload.TopRouter = ctx.TopRouter
						payload.Hits = ctx.Hits
						payload.Count4xx = ctx.Count4xx
						payload.Count5xx = ctx.Count5xx
						payload.ErrorRate = ctx.ErrorRate
					}
					if err := w.notifier.SendAutoBlockAlert(payload); err != nil {
						slog.Warn("Telegram auto-block alert failed", "ip", alert.SuspectedIP, "err", err)
					}
				}
			}
		}
	}
}
