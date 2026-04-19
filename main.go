package main

import (
	"encoding/json"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/janus-project/janus/internal/pulse"
	"github.com/janus-project/janus/internal/security"
	"github.com/janus-project/janus/internal/traefik"
)

//go:embed web
var webFS embed.FS

// config holds all runtime configuration sourced from environment variables.
type config struct {
	TraefikURL     string
	Port           string
	PollInterval   time.Duration
	AlertThreshold float64 // error-rate threshold for Pulse alerts (0.0–1.0)
}

// statusResponse is the payload returned by GET /api/status.
type statusResponse struct {
	Timestamp     time.Time             `json:"timestamp"`
	TraefikOK     bool                  `json:"traefik_ok"`
	OverallScore  int                   `json:"overall_score"`
	RedFlags      []security.RedFlag    `json:"red_flags"`
	PulseAlerts   []pulse.ServiceAlert  `json:"pulse_alerts"`
	Overview      *traefik.Overview     `json:"overview,omitempty"`
	MetricsEnable bool                  `json:"metrics_enabled"`
	Error         string                `json:"error,omitempty"`
}

func main() {
	cfg := loadConfig()

	client := traefik.NewClient(cfg.TraefikURL)

	mux := http.NewServeMux()

	// Serve the embedded SPA. Strip the leading "web/" prefix so that
	// index.html is available at "/" rather than "/web/index.html".
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embed sub-FS: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))

	// API endpoint consumed by the dashboard.
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		resp := buildStatus(client, cfg.AlertThreshold)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			log.Printf("encode status: %v", err)
		}
	})

	addr := ":" + cfg.Port
	log.Printf("Janus listening on %s  |  Traefik API: %s", addr, cfg.TraefikURL)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// buildStatus fetches data from Traefik, runs analysis, and returns a
// fully-populated statusResponse. Errors are surfaced in the response body
// rather than HTTP 5xx so the dashboard always receives valid JSON.
func buildStatus(client *traefik.Client, alertThreshold float64) statusResponse {
	resp := statusResponse{
		Timestamp: time.Now().UTC(),
		RedFlags:  []security.RedFlag{},
		PulseAlerts: []pulse.ServiceAlert{},
	}

	resp.TraefikOK = client.Ping()
	if !resp.TraefikOK {
		resp.Error = "cannot reach Traefik API — is it running?"
		resp.OverallScore = 0
		return resp
	}

	// ── Overview ────────────────────────────────────────────────────────────
	overview, err := client.FetchOverview()
	if err != nil {
		log.Printf("overview: %v", err)
	} else {
		resp.Overview = overview
		resp.MetricsEnable = overview.Features.Metrics != ""
	}

	// ── Security analysis ───────────────────────────────────────────────────
	raw, err := client.FetchRawData()
	if err != nil {
		resp.Error = fmt.Sprintf("rawdata: %v", err)
		resp.OverallScore = 0
		return resp
	}

	flags, score := security.Analyze(raw)
	resp.RedFlags = flags
	resp.OverallScore = score

	// ── Pulse monitor (requires Prometheus metrics enabled in Traefik) ──────
	if resp.MetricsEnable {
		metricsText, err := client.FetchMetrics()
		if err != nil {
			log.Printf("metrics: %v", err)
		} else {
			resp.PulseAlerts = pulse.Analyze(metricsText, alertThreshold)
		}
	}

	return resp
}

func loadConfig() config {
	cfg := config{
		TraefikURL:     getEnv("TRAEFIK_API_URL", "http://traefik:8080"),
		Port:           getEnv("JANUS_PORT", "9090"),
		AlertThreshold: 0.10,
	}

	if v := os.Getenv("JANUS_ALERT_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			cfg.AlertThreshold = f
		}
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
