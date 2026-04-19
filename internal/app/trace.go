package app

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/janus-project/janus/domain"
)

type auditTraceEntry struct {
	Timestamp        time.Time `json:"timestamp"`
	PromptTokens     int       `json:"prompt_tokens"`
	CompletionTokens int       `json:"completion_tokens"`
	TotalTokens      int       `json:"total_tokens"`
	LatencyMs        int64     `json:"latency_ms"`
	OverallScore     int       `json:"overall_score"`
	Severity         int       `json:"severity"`
	ShadowAPICount   int       `json:"shadow_api_count"`
	Fallback         bool      `json:"fallback"`
	Summary          string    `json:"summary"`
}

// WriteAuditTrace appends one JSONL record to the AI audit trace file.
// Each line is a self-contained JSON object so the file is streamable.
// If path is empty or AIInsights is nil the call is a no-op.
func WriteAuditTrace(path string, report domain.AuditReport) {
	if path == "" || report.AIInsights == nil {
		return
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("audit trace: cannot create log dir", "path", path, "err", err)
		return
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		slog.Warn("audit trace: cannot open file", "path", path, "err", err)
		return
	}
	defer f.Close()

	ai := report.AIInsights
	entry := auditTraceEntry{
		Timestamp:        ai.GeneratedAt,
		PromptTokens:     ai.PromptTokens,
		CompletionTokens: ai.CompletionTokens,
		TotalTokens:      ai.TokensUsed,
		LatencyMs:        ai.LatencyMs,
		OverallScore:     report.OverallScore,
		Severity:         ai.Severity,
		ShadowAPICount:   len(ai.ShadowAPIs),
		Fallback:         ai.Fallback,
		Summary:          ai.Summary,
	}

	line, err := json.Marshal(entry)
	if err != nil {
		slog.Warn("audit trace: marshal failed", "err", err)
		return
	}

	if _, err := f.Write(append(line, '\n')); err != nil {
		slog.Warn("audit trace: write failed", "err", err)
	}
}
