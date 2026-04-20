# Changelog

All notable changes to Janus are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Janus uses [Semantic Versioning](https://semver.org/).

---

## [0.9.0] — 2026-04-20

### Added — Stage 9: DDD Refactor & Test Coverage

- `internal/web/api/` — new HTTP adapter package isolating every handler from `main.go`
  - `dto.go` — all JSON response types (`StatusResponse`, `OverviewDTO`, `RouterAuditDTO`, `AIInsightsDTO`, …); JSON tags live here so `domain/` stays pure
  - `converters.go` — domain → DTO mappers (Anti-Corruption Layer)
  - `server.go` — `Server` struct holding all collaborators; `Handler()` registers every route including `/auth`, `/api/status`, `/api/v1/history`, `/api/v1/trend`, `/api/v1/shield/*`, `/api/v1/intel/*`, `/api/v1/ai/*`
- Unit tests for pure-logic packages: `internal/pulse/monitor_test.go`, `internal/security/auditor_test.go`, `internal/app/policy_test.go`, `internal/infrastructure/firewall/shield_test.go`
- **Shield tab — Trusted IPs management**: inline add/remove UI (formerly split between Shield read-only pills and Intelligence management)

### Changed

- Graceful shutdown via `signal.NotifyContext(SIGINT, SIGTERM)` + `sync.WaitGroup` + `http.Server.Shutdown` with a 10 s deadline; every worker exits cleanly on Ctrl-C
- `cmd/janus/main.go` shrank from ~994 lines to ~300 lines — now pure wiring (config, dependency construction, worker/server lifecycle)
- Trusted IPs management relocated from Intelligence tab to Shield tab so all IP controls (Trusted, Blocked, Admin Allowlist) live in one place
- Block-IP flow warns when the target is already trusted and links to the Trusted IPs section

### Fixed

- `Shield.IsBlocked` now checks immunity **before** the blocklist, preventing lockout when an already-blocked IP is later added to the trusted list
- `FetchMetrics` uses `io.ReadAll` instead of a manual byte-buffer loop
- `storage.SQLiteRepository` now logs `rows.Scan` errors via `slog.Warn` instead of swallowing them
- Removed dead `fireDriftAlerts`; `app/review.go` verdict "C" label clarified to `INCONCLUSIVE`

---

## [0.8.0] — 2026-04-20

### Added — Stage 8: Threat Intelligence & Geo-Reporting

- `internal/infrastructure/geoip/reader.go` — MaxMind GeoLite2-City `.mmdb` wrapper; graceful no-op when database is absent
- `internal/infrastructure/logs/analyzer.go` — `TrafficAnalyzer`: polls the Traefik access log every 60 s, aggregates all HTTP requests per IP (2xx / 4xx / 5xx counts, error rate, top router) over a sliding 1-hour retention window; `TopIPs(n)` and `UniqueIPCount()`
- `internal/infrastructure/llm/intel_prompt.go` — `IntelSystemPrompt`: structured JSON schema asking the LLM to classify every IP (HOSTILE / SUSPICIOUS / LEGITIMATE / UNKNOWN), identify hostile clusters, summarise attacker nations, and write a 3-paragraph executive threat assessment
- `internal/app/intel.go` — `ThreatIntelService` orchestrating geo-enriched traffic profiles → LLM → `ThreatIntelReport`; `AnalyzeAsync()` (no-op if already running); `MarkdownReport()` with Unicode country-flag emojis
- `GET /api/v1/intel` — returns the latest `ThreatIntelReport` as JSON
- `POST /api/v1/intel/analyze` — triggers a background threat intelligence analysis cycle
- `GET /api/v1/intel/report` — downloads the full AI-written Markdown threat report
- **Intelligence tab**: IP table (country, city, hits, error %, router, AI verdict), hostile cluster cards, attacker-nations table, Run Analysis and Download Report buttons
- `JANUS_GEOIP_DB_PATH` env var (default `/app/data/GeoLite2-City.mmdb`)

### Fixed

- Unblock and aggressivity block buttons were silently broken: `JSON.stringify(ip)` embedded double-quoted strings inside double-quoted HTML `onclick` attributes, preventing the JS from executing. Fixed with single-quoted `esc()` arguments.

---

## [0.7.0] — 2026-04-20

### Added — Stage 7.1: AI-Driven "Watch & Forgive"

- `internal/infrastructure/logs/tailer.go` — `AccessLogTailer`: polls Traefik's JSON access log every 5 s; records HTTP 403 hits per IP in a bounded ring buffer (1 000 hits / IP); handles log rotation; `BucketHits()` for 6 × 5-min sparklines
- `internal/infrastructure/llm/review_prompt.go` — `ReviewSystemPrompt` instructing the LLM to decide A (extend) / B (unblock) / C (maintain)
- `internal/app/review.go` — `BanReviewWorker`: 30-min ticker reviews all blocked IPs; auto-calls `shield.UnblockIP()` on verdict B; stores verdicts in memory for Shield tab display
- `GET /api/v1/shield` extended to return per-IP sparkline buckets, hit count, AI verdict, label, reasoning, and review timestamp
- Shield tab enriched with SVG sparklines, PERSISTENT ATTACKER / COOLING DOWN badges, and AI reasoning text
- `JANUS_ACCESS_LOG_PATH` env var (default `/logs/access.log`)

---

## [0.6.0] — 2026-04-20

### Added — Stage 7: Active Defense (The Shield)

- `internal/infrastructure/firewall/shield.go` — `ShieldService`: manages `JANUS_SHIELD_PATH` YAML; `BlockIP`, `UnblockIP`, `ListBlocked`; pure-Go line-level YAML parser; Traefik-compatible `ipAllowList` / `excludedIPs` output
- Auto Fail2Ban: `AggressivityAlert` gains `SuspectedIP`; AI prompt requests `suspected_ip`; `fireThreatAlerts()` blocks when severity ≥ `JANUS_AUTO_BLOCK_MIN` and a suspected IP is present; fires IP_BANNED Telegram alert
- `POST /api/v1/shield/block` and `POST /api/v1/shield/unblock` endpoints
- **Shield tab**: blocked IP list with Unblock buttons, manual block form, Traefik wiring hint
- Bot-scan aggressivity alerts show "🚫 Block {ip}" / "🚫 Block Last Attacker" buttons
- `JANUS_SHIELD_PATH` (default `/rules/blocklist.yaml`) and `JANUS_AUTO_BLOCK_MIN` (default `10`) env vars

---

## [0.5.0] — 2026-04-20

### Added — Stage 6: Persistent Memory (SQLite)

- `internal/infrastructure/storage/sqlite.go` — `SQLiteRepository` using `modernc.org/sqlite` (pure Go, no CGo); tables `audits` and `router_results`; auto-migration on startup
- `storage.RichStore` interface with `GetSecurityTrend(days int)`
- `GET /api/v1/trend?days=N` endpoint (SQLite only; defaults to 30 days)
- `ConsultService` now accepts `storage.Store` interface — works with both SQLite and JSON backends
- `JANUS_DB_PATH` env var (default `/app/data/janus.db`); falls back to JSON file when unset

---

## [0.4.0] — 2026-04-20

### Added — Stage 5: Security Advisor & Policy Enforcement

- `domain/policy.go`, `internal/app/policy.go`, `configs/policies.json` — `LoadPolicies()` reads a JSON file; `CheckPolicies()` applies glob-pattern matching; default policies embedded in binary (admin, API, public, dashboard, monitoring)
- `internal/app/drift.go` — `DetectDrift()` compares consecutive `AuditReport`s; produces `DriftAlert` entries shown as an orange banner and triggering a Telegram alert
- `GET /api/v1/ai/consult` — sends full audit history to the LLM for a 3-paragraph executive summary
- **Policies tab**: policy definitions, per-router compliance status, inline "Ask Janus-AI" consult button
- `JANUS_POLICIES_PATH` env var (default `/configs/policies.json`)

---

## [0.3.0] — 2026-04-20

### Added — Stage 4: Automated Remediation & Alerts

- `internal/app/remediation.go` — `FormatDockerLabels()` generates copy-pasteable Traefik label blocks from AI remediation strings or heuristic issue codes
- `internal/infrastructure/telegram/notifier.go` — fires Telegram alerts on bot_scan + severity ≥ threshold
- `internal/infrastructure/storage/repository.go` — JSON-file audit history (last 100 entries); `GET /api/v1/history` endpoint
- "📋 Copy Fix" button on every router card
- Intelligence History section: sparkline bar chart + sortable 20-entry audit table
- `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_SEVERITY_THRESHOLD` env vars

---

## [0.2.0] — 2026-04-20

### Added — Stages 2 & 3: Infrastructure, AI Integration, Deep-Context Auditor

- `internal/infrastructure/traefik` — typed HTTP client; Anti-Corruption Layer mapping Traefik DTOs → domain entities
- `internal/infrastructure/llm` — vLLM OpenAI-compatible client; chain-of-thought system prompt with per-router attack surface + remediation, severity 0–10, architectural drift analysis
- `internal/infrastructure/llm/analyst.go` — maps LLM response to `domain.AIInsights`; returns `Fallback: true` on error
- `internal/app/worker.go` — `AIAuditWorker`: 60-second background ticker; JSONL audit trace at `JANUS_AI_TRACE_PATH`
- `internal/app/context.go` — `ParseKnownMiddlewares()`; full Traefik rawdata context builder
- `internal/app/trace.go` — JSONL trace writer with token counts and severity
- `GET /api/v1/ai-insights` endpoint
- Dashboard AI section: summary, chain-of-thought block, correlations, shadow APIs, traffic classification, per-router deep-analysis cards
- DDD domain layer: `domain/analyst.go`, `domain/policy.go`; `Auditor` interface; `RouterInsight`, `AIInsights`, `DriftAlert` types
- `VLLM_API_URL`, `VLLM_MODEL`, `VLLM_API_KEY`, `JANUS_ENV`, `JANUS_KNOWN_MIDDLEWARES`, `JANUS_AI_TRACE_PATH` env vars

---

## [0.1.0] — 2026-04-19

### Added — Stage 1: Foundation

- `internal/traefik/client.go` — typed HTTP client for Traefik's `/api/rawdata`, `/api/overview`, `/metrics`, and `/ping` endpoints
- `internal/security/scorer.go` — Security Scorer: per-router analysis flagging missing TLS, auth, rate-limit, and IP-allowlist middlewares; overall 0–100 score
- `internal/pulse/monitor.go` — Pulse Monitor: zero-dependency Prometheus text parser; alerts on services exceeding a configurable 4xx+5xx error-rate threshold
- `cmd/janus/main.go` — single-binary HTTP server; `/api/status` JSON endpoint; `//go:embed` SPA
- `internal/web/static/index.html` — dark-mode Tailwind dashboard with score ring gauge, router red-flag cards, and Pulse error-rate bars; 30-second auto-refresh
- `Dockerfile` — multi-stage build producing a `scratch`-based image (~6 MB)
- `docker-compose.yml` — joins existing `proxy-network` external network
- `.env` / `.env.example` — full environment variable documentation; Portainer-friendly
