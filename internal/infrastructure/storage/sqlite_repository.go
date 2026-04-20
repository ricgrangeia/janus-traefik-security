package storage

import (
	"database/sql"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // register "sqlite" driver with database/sql
)

// SQLiteRepository implements RichStore using an embedded SQLite database.
// All methods are safe for concurrent use.
type SQLiteRepository struct {
	db *sql.DB
	mu sync.Mutex
}

// NewSQLiteRepository opens (or creates) the SQLite database at path,
// runs all pending migrations, and returns a ready-to-use repository.
func NewSQLiteRepository(path string) (*SQLiteRepository, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// SQLite performs best with a single writer; allow multiple readers.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := migrateUp(db); err != nil {
		return nil, err
	}

	slog.Info("SQLite database ready", "path", path)
	return &SQLiteRepository{db: db}, nil
}

// ── Store interface ───────────────────────────────────────────────────────

// Save persists a summary to the audits table (satisfies the basic Store interface).
func (r *SQLiteRepository) Save(s AuditSummary) {
	r.mu.Lock()
	defer r.mu.Unlock()

	_, err := r.db.Exec(`
		INSERT INTO audits
			(timestamp, overall_score, ai_severity, total_issues, shadow_api_count,
			 drift_count, tokens_used, latency_ms, is_fallback)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.Timestamp, s.OverallScore, s.Severity, s.RedFlags,
		s.ShadowAPIs, 0, s.TokensUsed, s.LatencyMs, boolInt(s.Fallback),
	)
	if err != nil {
		slog.Warn("SQLite: save audit failed", "err", err)
	}
}

// History returns the last 100 audit summaries, oldest first.
func (r *SQLiteRepository) History() []AuditSummary {
	r.mu.Lock()
	defer r.mu.Unlock()

	rows, err := r.db.Query(`
		SELECT timestamp, overall_score, ai_severity, total_issues,
		       shadow_api_count, tokens_used, latency_ms, is_fallback
		FROM audits
		ORDER BY timestamp DESC
		LIMIT 100`)
	if err != nil {
		slog.Warn("SQLite: history query failed", "err", err)
		return nil
	}
	defer rows.Close()

	var out []AuditSummary
	for rows.Next() {
		var s AuditSummary
		var ts string
		var fallback int
		if err := rows.Scan(&ts, &s.OverallScore, &s.Severity, &s.RedFlags,
			&s.ShadowAPIs, &s.TokensUsed, &s.LatencyMs, &fallback); err != nil {
			slog.Warn("SQLite: history row scan failed", "err", err)
			continue
		}
		s.Timestamp, _ = time.Parse(time.RFC3339, ts)
		s.Fallback = fallback != 0
		out = append(out, s)
	}
	// Return oldest first.
	reverse(out)
	return out
}

// ── RichStore interface ───────────────────────────────────────────────────

// SaveAuditWithRouters inserts the audit row and all router results in a
// single transaction. Returns the new audit ID.
func (r *SQLiteRepository) SaveAuditWithRouters(summary AuditSummary, routers []RouterResult) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	tx, err := r.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	res, err := tx.Exec(`
		INSERT INTO audits
			(timestamp, overall_score, ai_severity, total_issues, shadow_api_count,
			 drift_count, tokens_used, latency_ms, is_fallback)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		summary.Timestamp, summary.OverallScore, summary.Severity, summary.RedFlags,
		summary.ShadowAPIs, 0, summary.TokensUsed, summary.LatencyMs, boolInt(summary.Fallback),
	)
	if err != nil {
		return 0, err
	}
	auditID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	for _, rr := range routers {
		if _, err := tx.Exec(`
			INSERT INTO router_results
				(audit_id, router_name, score, severity, ai_reasoning, remediation_snippet, issue_codes)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			auditID, rr.RouterName, rr.Score, rr.Severity,
			rr.AIReasoning, rr.RemediationSnippet, rr.IssueCodes,
		); err != nil {
			slog.Warn("SQLite: insert router_result failed", "router", rr.RouterName, "err", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return auditID, nil
}

// GetSecurityTrend returns audit summaries for the last n days, oldest first.
func (r *SQLiteRepository) GetSecurityTrend(days int) []AuditSummary {
	r.mu.Lock()
	defer r.mu.Unlock()

	since := time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339)
	rows, err := r.db.Query(`
		SELECT timestamp, overall_score, ai_severity, total_issues,
		       shadow_api_count, tokens_used, latency_ms, is_fallback
		FROM audits
		WHERE timestamp >= ?
		ORDER BY timestamp ASC`, since)
	if err != nil {
		slog.Warn("SQLite: trend query failed", "err", err)
		return nil
	}
	defer rows.Close()

	var out []AuditSummary
	for rows.Next() {
		var s AuditSummary
		var ts string
		var fallback int
		if err := rows.Scan(&ts, &s.OverallScore, &s.Severity, &s.RedFlags,
			&s.ShadowAPIs, &s.TokensUsed, &s.LatencyMs, &fallback); err != nil {
			slog.Warn("SQLite: trend row scan failed", "err", err)
			continue
		}
		s.Timestamp, _ = time.Parse(time.RFC3339, ts)
		s.Fallback = fallback != 0
		out = append(out, s)
	}
	return out
}

// GetLatestScores returns the n most recent overall_score values, newest first.
func (r *SQLiteRepository) GetLatestScores(n int) []int {
	r.mu.Lock()
	defer r.mu.Unlock()

	rows, err := r.db.Query(`
		SELECT overall_score FROM audits
		ORDER BY timestamp DESC LIMIT ?`, n)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var scores []int
	for rows.Next() {
		var s int
		if rows.Scan(&s) == nil {
			scores = append(scores, s)
		}
	}
	return scores
}

// ── Helpers ───────────────────────────────────────────────────────────────

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func reverse(s []AuditSummary) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// IssueCodesCSV converts a slice of issue codes to a comma-separated string.
func IssueCodesCSV(codes []string) string {
	return strings.Join(codes, ",")
}
