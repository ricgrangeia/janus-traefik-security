# Janus — Traefik Security Bridge

> **Version:** 0.1.0 · **License:** MIT · **Stack:** Go · Docker · Tailwind CSS

Janus is a lightweight Go sidecar that runs alongside Traefik and bridges the gap between **DevOps** (who configures the proxy) and **Developers** (who need to understand what is exposed and how). It surfaces security gaps and error-rate anomalies that standard server logs miss — in a single, embedded dashboard.

---

## Architecture

![Janus Architecture](docs/infographic.svg)

Janus sits inside the same Docker network as Traefik (`proxy-network`) and polls Traefik's internal REST API. It never intercepts live traffic — it is a **read-only observer**.

---

## Core Features

### Data Bridge

Connects to Traefik's `/api/rawdata`, `/api/overview`, and `/metrics` endpoints via a typed Go HTTP client. No external dependencies — pure standard library.

### Security Scorer (`internal/security`)

Analyses every non-internal router and produces a **score from 0 to 100**. Points are deducted for:

| Issue | Deduction |
| --- | --- |
| No authentication middleware (`basicAuth` / `forwardAuth` / `digestAuth`) | −40 |
| No TLS on a public entrypoint (`web`, `websecure`) | −30 |
| No rate-limit middleware | −20 |
| No IP allowlist middleware | −10 |

The overall score is the average across all routers.

### Pulse Monitor (`internal/pulse`)

Parses Traefik's Prometheus text format without any third-party library. Aggregates `traefik_service_requests_total` per service and raises an alert when the combined **4xx + 5xx error rate** exceeds the configured threshold (default: 10 %). High error rates often indicate bot probing or upstream failures.

> Requires `--metrics.prometheus=true` in Traefik. Already included in the provided `docker-compose.yml`.

### Embedded Dashboard

Single-page dark-mode UI (`web/index.html`) compiled into the binary via `//go:embed`. Features:

- Score ring gauge (color-coded: green / amber / red)
- Router red-flag cards sorted by score, worst first
- Pulse error-rate bars per service
- 30-second auto-refresh with manual override

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- An existing Traefik container attached to a Docker network named `proxy-network`

### Run

```bash
# 1. Clone
git clone https://github.com/janus-project/janus.git
cd janus

# 2. Copy and review environment config
cp .env.example .env

# 3. Start
docker compose up --build -d

# 4. Open the dashboard
open http://localhost:9090
```

---

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `TRAEFIK_API_URL` | `http://traefik:8080` | Base URL of Traefik's API (no trailing slash) |
| `JANUS_PORT` | `9090` | Port Janus listens on inside the container |
| `JANUS_ALERT_THRESHOLD` | `0.10` | Pulse alert threshold — fraction of error requests (0.0–1.0) |

> **Portainer:** set these directly in the stack's "Environment variables" panel. No `.env` file needed.

---

## Project Structure

```text
janus/
├── main.go                   # HTTP server, /api/status handler, embed wiring
├── go.mod                    # No external dependencies
├── Dockerfile                # Multi-stage → scratch image (~6 MB)
├── docker-compose.yml        # Joins external proxy-network
├── .env.example              # Environment variable template
├── VERSION                   # Current version (SemVer)
├── CHANGELOG.md              # Release history
├── docs/
│   └── infographic.svg       # Architecture diagram
├── internal/
│   ├── traefik/client.go     # Traefik API client + typed response structs
│   ├── security/scorer.go    # Security analysis engine
│   └── pulse/monitor.go      # Prometheus text parser + error-rate alerts
└── web/
    └── index.html            # Embedded Tailwind SPA
```

---

## API

`GET /api/status` — returns a JSON snapshot used by the dashboard.

```json
{
  "timestamp": "2026-04-19T10:00:00Z",
  "traefik_ok": true,
  "overall_score": 55,
  "red_flags": [
    {
      "router_name": "api@docker",
      "rule": "Host(`api.example.com`)",
      "score": 30,
      "issues": [
        "No authentication middleware (basicAuth / forwardAuth / digestAuth)",
        "No TLS configured on public entrypoint"
      ]
    }
  ],
  "pulse_alerts": [
    {
      "service_name": "api@docker",
      "total_requests": 8400,
      "count_4xx": 980,
      "count_5xx": 120,
      "error_rate": 0.131
    }
  ],
  "metrics_enabled": true
}
```

---

## Docker Network

Janus joins the **existing** `proxy-network` as an external network — it never creates or owns it. If the network does not exist, Docker will fail at deploy time (intentional fail-fast behavior).

```yaml
networks:
  proxy-network:
    external: true
```

---

## Versioning

Janus follows [Semantic Versioning](https://semver.org/). The current version is tracked in [VERSION](VERSION) and release history in [CHANGELOG.md](CHANGELOG.md).

---

## Philosophy

Janus (the two-faced Roman god) looks in two directions simultaneously:

- **Inward** — reads Traefik's internal state via its API
- **Outward** — presents a clear, actionable summary for both teams

It does not replace Traefik's dashboard, Prometheus, or Grafana. It is the **fast, zero-configuration bridge** for teams who need situational awareness without standing up a full observability stack.

---

## License

MIT — see [LICENSE](LICENSE).
