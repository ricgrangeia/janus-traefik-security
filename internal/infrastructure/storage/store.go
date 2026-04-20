package storage

// Store is the minimal interface implemented by both the JSON and SQLite repositories.
// The worker only depends on this interface.
type Store interface {
	Save(AuditSummary)
	History() []AuditSummary
}

// RichStore extends Store with detailed per-audit router persistence and trend queries.
// Implemented only by SQLiteRepository.
type RichStore interface {
	Store
	SaveAuditWithRouters(summary AuditSummary, routers []RouterResult) (int64, error)
	GetSecurityTrend(days int) []AuditSummary
	GetLatestScores(n int) []int // newest first
}

// RouterResult stores per-router details for a single audit.
type RouterResult struct {
	RouterName         string
	Score              int
	Severity           int
	AIReasoning        string
	RemediationSnippet string
	IssueCodes         string // comma-separated SEC-001,SEC-003...
}
