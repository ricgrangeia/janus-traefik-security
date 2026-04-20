// Package storage persists AI audit summaries for trend analysis.
package storage

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxHistory = 100

// AuditSummary is a lightweight record of one AI audit cycle.
type AuditSummary struct {
	Timestamp    time.Time `json:"timestamp"`
	OverallScore int       `json:"overall_score"`
	Severity     int       `json:"severity"`
	RedFlags     int       `json:"red_flags"`
	ShadowAPIs   int       `json:"shadow_apis"`
	TokensUsed   int       `json:"tokens_used"`
	LatencyMs    int64     `json:"latency_ms"`
	Fallback     bool      `json:"fallback"`
}

// Repository stores audit summaries to a JSON file and provides trend data.
// All methods are safe for concurrent use.
type Repository struct {
	path    string
	mu      sync.Mutex
	history []AuditSummary
}

// NewRepository opens (or creates) the history file at path.
func NewRepository(path string) *Repository {
	r := &Repository{path: path}
	r.load()
	return r
}

// Save appends a summary, keeps only the last maxHistory entries, and flushes to disk.
func (r *Repository) Save(s AuditSummary) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.history = append(r.history, s)
	if len(r.history) > maxHistory {
		r.history = r.history[len(r.history)-maxHistory:]
	}
	r.flush()
}

// History returns a copy of all stored summaries, oldest first.
func (r *Repository) History() []AuditSummary {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]AuditSummary, len(r.history))
	copy(out, r.history)
	return out
}

func (r *Repository) load() {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return // file does not exist yet — fine
	}
	if err := json.Unmarshal(data, &r.history); err != nil {
		slog.Warn("storage: history file corrupted, starting fresh", "err", err)
		r.history = nil
	}
}

func (r *Repository) flush() {
	if r.path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o755); err != nil {
		slog.Warn("storage: cannot create dir", "path", r.path, "err", err)
		return
	}
	data, err := json.MarshalIndent(r.history, "", "  ")
	if err != nil {
		slog.Warn("storage: marshal failed", "err", err)
		return
	}
	if err := os.WriteFile(r.path, data, 0o644); err != nil {
		slog.Warn("storage: write failed", "path", r.path, "err", err)
	}
}
