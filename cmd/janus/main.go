package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/janus-project/janus/domain"
	traefikinfra "github.com/janus-project/janus/internal/infrastructure/traefik"
	"github.com/janus-project/janus/internal/pulse"
	"github.com/janus-project/janus/internal/security"
	janusWeb "github.com/janus-project/janus/internal/web"
)

// config holds all runtime configuration sourced from environment variables.
type config struct {
	TraefikURL     string
	Port           string
	AlertThreshold float64
}

// ── API response DTOs ─────────────────────────────────────────────────────
// These structs carry JSON tags and live in the application layer,
// keeping the domain models free of serialisation concerns.

type statusResponse struct {
	Timestamp      time.Time        `json:"timestamp"`
	TraefikOK      bool             `json:"traefik_ok"`
	OverallScore   int              `json:"overall_score"`
	RedFlags       []routerAuditDTO `json:"red_flags"`
	PulseAlerts    []pulseAlertDTO  `json:"pulse_alerts"`
	MetricsEnabled bool             `json:"metrics_enabled"`
	Overview       *overviewDTO     `json:"overview,omitempty"`
	Error          string           `json:"error,omitempty"`
}

type overviewDTO struct {
	HTTP      httpStatsDTO `json:"http"`
	Providers []string     `json:"providers"`
}

type httpStatsDTO struct {
	Routers     entityStatsDTO `json:"routers"`
	Services    entityStatsDTO `json:"services"`
	Middlewares entityStatsDTO `json:"middlewares"`
}

type entityStatsDTO struct {
	Total    int `json:"total"`
	Warnings int `json:"warnings"`
	Errors   int `json:"errors"`
}

type routerAuditDTO struct {
	RouterName string     `json:"router_name"`
	Rule       string     `json:"rule"`
	Provider   string     `json:"provider"`
	Issues     []issueDTO `json:"issues"`
	Score      int        `json:"score"`
	IsRedirect bool       `json:"is_redirect"`
}

type issueDTO struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type pulseAlertDTO struct {
	ServiceName string  `json:"service_name"`
	Total       float64 `json:"total_requests"`
	Count4xx    float64 `json:"count_4xx"`
	Count5xx    float64 `json:"count_5xx"`
	ErrorRate   float64 `json:"error_rate"`
}

func main() {
	cfg := loadConfig()
	client := traefikinfra.NewClient(cfg.TraefikURL)
	auditor := security.NewAuditor()

	sub, err := fs.Sub(janusWeb.StaticFS, "static")
	if err != nil {
		log.Fatalf("embed sub-FS: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		resp := buildStatus(client, auditor, cfg.AlertThreshold)
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

// buildStatus fetches data from Traefik, builds a NetworkSnapshot, runs the
// Auditor, and converts the AuditReport to the API response DTO.
func buildStatus(client *traefikinfra.Client, auditor domain.Auditor, alertThreshold float64) statusResponse {
	resp := statusResponse{
		Timestamp:   time.Now().UTC(),
		RedFlags:    []routerAuditDTO{},
		PulseAlerts: []pulseAlertDTO{},
	}

	traefikOK := client.Ping()
	resp.TraefikOK = traefikOK

	if !traefikOK {
		resp.Error = "cannot reach Traefik API — is it running?"
		return resp
	}

	// ── Fetch raw data ───────────────────────────────────────────────────
	overview, err := client.FetchOverview()
	if err != nil {
		log.Printf("overview: %v", err)
	} else if overview != nil {
		resp.Overview = toOverviewDTO(overview)
	}

	raw, err := client.FetchRawData()
	if err != nil {
		resp.Error = fmt.Sprintf("rawdata: %v", err)
		return resp
	}

	// ── Pulse monitor ────────────────────────────────────────────────────
	var pulseAlerts []domain.PulseAlert
	metricsEnabled := overview != nil && overview.Features.Metrics != ""
	resp.MetricsEnabled = metricsEnabled

	if metricsEnabled {
		metricsText, err := client.FetchMetrics()
		if err != nil {
			log.Printf("metrics: %v", err)
		} else {
			pulseAlerts = pulse.Analyze(metricsText, alertThreshold)
		}
	}

	// ── Assemble snapshot and run domain Auditor ─────────────────────────
	snapshot := traefikinfra.ToSnapshot(raw, pulseAlerts, traefikOK)
	report := auditor.Audit(snapshot)

	resp.OverallScore = report.OverallScore
	resp.RedFlags = toRouterAuditDTOs(report.RouterAudits)
	resp.PulseAlerts = toPulseAlertDTOs(report.PulseAlerts)

	return resp
}

// ── DTO converters ────────────────────────────────────────────────────────

func toRouterAuditDTOs(audits []domain.RouterAudit) []routerAuditDTO {
	out := make([]routerAuditDTO, 0, len(audits))
	for _, a := range audits {
		dto := routerAuditDTO{
			RouterName: a.Router.Name,
			Rule:       a.Router.Rule,
			Provider:   a.Router.Provider,
			Score:      a.Score,
			IsRedirect: a.Router.IsRedirect,
			Issues:     make([]issueDTO, 0, len(a.Issues)),
		}
		for _, issue := range a.Issues {
			dto.Issues = append(dto.Issues, issueDTO{
				Code:        issue.Code,
				Description: issue.Description,
				Severity:    issue.Severity.String(),
			})
		}
		out = append(out, dto)
	}
	return out
}

func toPulseAlertDTOs(alerts []domain.PulseAlert) []pulseAlertDTO {
	out := make([]pulseAlertDTO, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, pulseAlertDTO{
			ServiceName: a.ServiceName,
			Total:       a.Total,
			Count4xx:    a.Count4xx,
			Count5xx:    a.Count5xx,
			ErrorRate:   a.ErrorRate,
		})
	}
	return out
}

func toOverviewDTO(ov *traefikinfra.OverviewDTO) *overviewDTO {
	return &overviewDTO{
		HTTP: httpStatsDTO{
			Routers:     entityStatsDTO{Total: ov.HTTP.Routers.Total, Warnings: ov.HTTP.Routers.Warnings, Errors: ov.HTTP.Routers.Errors},
			Services:    entityStatsDTO{Total: ov.HTTP.Services.Total, Warnings: ov.HTTP.Services.Warnings, Errors: ov.HTTP.Services.Errors},
			Middlewares: entityStatsDTO{Total: ov.HTTP.Middlewares.Total, Warnings: ov.HTTP.Middlewares.Warnings, Errors: ov.HTTP.Middlewares.Errors},
		},
		Providers: ov.Providers,
	}
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
