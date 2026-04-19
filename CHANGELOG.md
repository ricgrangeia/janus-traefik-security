# Changelog

All notable changes to Janus are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Janus uses [Semantic Versioning](https://semver.org/).

---

## [0.1.0] — 2026-04-19

### Added
- `internal/traefik` — typed HTTP client for Traefik's `/api/rawdata`, `/api/overview`, `/metrics`, and `/ping` endpoints
- `internal/security` — Security Scorer: per-router analysis flagging missing TLS, auth, rate-limit, and IP-allowlist middlewares; overall 0–100 score
- `internal/pulse` — Pulse Monitor: zero-dependency Prometheus text parser; alerts on services exceeding a configurable 4xx+5xx error-rate threshold
- `main.go` — single-binary HTTP server; `/api/status` JSON endpoint; `//go:embed` SPA
- `web/index.html` — dark-mode Tailwind dashboard with score ring gauge, router red-flag cards, and Pulse error-rate bars; 30-second auto-refresh
- `Dockerfile` — multi-stage build producing a `scratch`-based image (~6 MB)
- `docker-compose.yml` — joins existing `proxy-network` external network; no Traefik service ownership
- `.env` / `.env.example` — full environment variable documentation; Portainer-friendly
