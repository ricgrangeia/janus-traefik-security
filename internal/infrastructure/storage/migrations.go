package storage

import (
	"database/sql"
	"fmt"
)

type migration struct {
	version int
	sql     string
}

// dbMigrations are applied in order on first run and on version upgrades.
// Each migration is idempotent — safe to replay if the version table already records it.
var dbMigrations = []migration{
	{1, `
		CREATE TABLE IF NOT EXISTS schema_versions (
			version INTEGER PRIMARY KEY
		);
	`},
	{2, `
		CREATE TABLE IF NOT EXISTS audits (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp    DATETIME NOT NULL,
			overall_score INTEGER NOT NULL,
			ai_severity  INTEGER  NOT NULL DEFAULT 0,
			total_issues INTEGER  NOT NULL DEFAULT 0,
			shadow_api_count INTEGER NOT NULL DEFAULT 0,
			drift_count  INTEGER  NOT NULL DEFAULT 0,
			tokens_used  INTEGER  NOT NULL DEFAULT 0,
			latency_ms   INTEGER  NOT NULL DEFAULT 0,
			is_fallback  INTEGER  NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_audits_timestamp ON audits(timestamp);
	`},
	{3, `
		CREATE TABLE IF NOT EXISTS router_results (
			id                  INTEGER PRIMARY KEY AUTOINCREMENT,
			audit_id            INTEGER NOT NULL REFERENCES audits(id),
			router_name         TEXT    NOT NULL,
			score               INTEGER NOT NULL,
			severity            INTEGER NOT NULL DEFAULT 0,
			ai_reasoning        TEXT    NOT NULL DEFAULT '',
			remediation_snippet TEXT    NOT NULL DEFAULT '',
			issue_codes         TEXT    NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_rr_audit   ON router_results(audit_id);
		CREATE INDEX IF NOT EXISTS idx_rr_router  ON router_results(router_name);
	`},
}

// migrateUp runs all pending migrations in order.
func migrateUp(db *sql.DB) error {
	// Bootstrap the versions table itself (migration 1 is special).
	if _, err := db.Exec(dbMigrations[0].sql); err != nil {
		return fmt.Errorf("bootstrap schema_versions: %w", err)
	}

	for _, m := range dbMigrations[1:] {
		var exists int
		_ = db.QueryRow(`SELECT COUNT(*) FROM schema_versions WHERE version = ?`, m.version).Scan(&exists)
		if exists > 0 {
			continue
		}
		if _, err := db.Exec(m.sql); err != nil {
			return fmt.Errorf("migration %d: %w", m.version, err)
		}
		if _, err := db.Exec(`INSERT INTO schema_versions(version) VALUES(?)`, m.version); err != nil {
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
	}
	return nil
}
