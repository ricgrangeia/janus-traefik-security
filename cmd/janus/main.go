package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/janus-project/janus/domain"
	"github.com/janus-project/janus/internal/app"
	traefikinfra "github.com/janus-project/janus/internal/infrastructure/traefik"
	"github.com/janus-project/janus/internal/infrastructure/llm"
	"github.com/janus-project/janus/internal/pulse"
	"github.com/janus-project/janus/internal/security"
	janusWeb "github.com/janus-project/janus/internal/web"
)

// config holds all runtime configuration sourced from environment variables.
type config struct {
	TraefikURL       string
	Port             string
	AlertThreshold   float64
	VLLMEnabled      bool
	VLLMURL          string
	VLLMModel        string
	VLLMAPIKey       string
	AIAuditInterval  time.Duration
	JanusEnv         string
	KnownMiddlewares string // raw CSV, parsed before use
	AITracePath      string
}

// ── API response DTOs ─────────────────────────────────────────────────────
// JSON tags live here — never in the domain layer.

type statusResponse struct {
	Timestamp      time.Time        `json:"timestamp"`
	TraefikOK      bool             `json:"traefik_ok"`
	OverallScore   int              `json:"overall_score"`
	RedFlags       []routerAuditDTO `json:"red_flags"`
	PulseAlerts    []pulseAlertDTO  `json:"pulse_alerts"`
	MetricsEnabled bool             `json:"metrics_enabled"`
	Overview       *overviewDTO     `json:"overview,omitempty"`
	AIInsights     *aiInsightsDTO   `json:"ai_insights,omitempty"`
	AIEnabled      bool             `json:"ai_enabled"`
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
	RouterName  string     `json:"router_name"`
	Rule        string     `json:"rule"`
	Provider    string     `json:"provider"`
	Issues      []issueDTO `json:"issues"`
	Score       int        `json:"score"`
	IsRedirect  bool       `json:"is_redirect"`
	AIReasoning string     `json:"ai_reasoning,omitempty"`
}

type issueDTO struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	AIReasoning string `json:"ai_reasoning,omitempty"`
}

type pulseAlertDTO struct {
	ServiceName string  `json:"service_name"`
	Total       float64 `json:"total_requests"`
	Count4xx    float64 `json:"count_4xx"`
	Count5xx    float64 `json:"count_5xx"`
	ErrorRate   float64 `json:"error_rate"`
}

type aiInsightsDTO struct {
	Thought            string                       `json:"thought,omitempty"`
	Summary            string                       `json:"summary"`
	Severity           int                          `json:"severity"`
	Correlations       []string                     `json:"correlations"`
	ShadowAPIs         []shadowAPIDTO               `json:"shadow_apis"`
	AggressivityAlerts []aggressivityDTO            `json:"aggressivity_alerts"`
	RouterInsights     map[string]routerInsightDTO  `json:"router_insights,omitempty"`
	PromptTokens       int                          `json:"prompt_tokens"`
	CompletionTokens   int                          `json:"completion_tokens"`
	TokensUsed         int                          `json:"tokens_used"`
	LatencyMs          int64                        `json:"latency_ms"`
	GeneratedAt        time.Time                    `json:"generated_at"`
	Fallback           bool                         `json:"fallback"`
}

type shadowAPIDTO struct {
	RouterName string `json:"router_name"`
	Reason     string `json:"reason"`
}

type aggressivityDTO struct {
	ServiceName string `json:"service_name"`
	Assessment  string `json:"assessment"`
	Reasoning   string `json:"reasoning"`
}

type routerInsightDTO struct {
	Analysis      string   `json:"analysis"`
	AttackSurface string   `json:"attack_surface"`
	Severity      int      `json:"severity"`
	Remediation   []string `json:"remediation"`
}

func main() {
	cfg := loadConfig()

	slog.Info("Janus starting",
		"port", cfg.Port,
		"traefik_url", cfg.TraefikURL,
		"ai_enabled", cfg.VLLMEnabled,
		"env", cfg.JanusEnv,
	)

	client  := traefikinfra.NewClient(cfg.TraefikURL)
	auditor := security.NewAuditor()

	// ── Optional AI worker ────────────────────────────────────────────────
	var aiWorker *app.AIAuditWorker
	if cfg.VLLMEnabled {
		knownMiddlewares := app.ParseKnownMiddlewares(cfg.KnownMiddlewares)
		llmClient        := llm.NewClient(cfg.VLLMURL, cfg.VLLMModel, cfg.VLLMAPIKey)
		analyst          := llm.NewAnalyst(llmClient, cfg.JanusEnv, knownMiddlewares)
		aiWorker          = app.NewAIAuditWorker(
			client, auditor, analyst,
			cfg.AlertThreshold, cfg.AIAuditInterval, cfg.AITracePath,
		)
		ctx, cancel := context.WithCancel(context.Background())
		_ = cancel // cancel on process exit (Go runtime handles SIGTERM)
		go aiWorker.Run(ctx)
	}

	// ── HTTP server ───────────────────────────────────────────────────────
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

		var latestInsights *domain.AIInsights
		if aiWorker != nil {
			latestInsights = aiWorker.LatestInsights()
		}

		resp := buildStatus(client, auditor, cfg.AlertThreshold, cfg.VLLMEnabled, latestInsights)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("encode status response", "err", err)
		}
	})

	// GET /api/v1/ai-insights — serves the latest AI reasoning text for human review.
	mux.HandleFunc("/api/v1/ai-insights", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		if aiWorker == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "AI features disabled — set VLLM_API_URL to enable"})
			return
		}

		insights := aiWorker.LatestInsights()
		if insights == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if err := json.NewEncoder(w).Encode(toAIInsightsDTO(insights)); err != nil {
			slog.Error("encode ai-insights response", "err", err)
		}
	})

	addr := ":" + cfg.Port
	slog.Info("Janus ready", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// buildStatus runs the regular (synchronous) security audit and overlays the
// latest AI insights from the background worker if available.
func buildStatus(
	client *traefikinfra.Client,
	auditor domain.Auditor,
	alertThreshold float64,
	aiEnabled bool,
	latestInsights *domain.AIInsights,
) statusResponse {
	resp := statusResponse{
		Timestamp:   time.Now().UTC(),
		RedFlags:    []routerAuditDTO{},
		PulseAlerts: []pulseAlertDTO{},
		AIEnabled:   aiEnabled,
	}

	traefikOK := client.Ping()
	resp.TraefikOK = traefikOK

	if !traefikOK {
		resp.Error = "cannot reach Traefik API — is it running?"
		return resp
	}

	overview, err := client.FetchOverview()
	if err != nil {
		slog.Warn("fetch overview failed", "err", err)
	} else if overview != nil {
		resp.Overview = toOverviewDTO(overview)
	}

	raw, err := client.FetchRawData()
	if err != nil {
		resp.Error = fmt.Sprintf("rawdata: %v", err)
		return resp
	}

	var pulseAlerts []domain.PulseAlert
	metricsEnabled := overview != nil && overview.Features.Metrics != ""
	resp.MetricsEnabled = metricsEnabled
	if metricsEnabled {
		if metricsText, err := client.FetchMetrics(); err == nil {
			pulseAlerts = pulse.Analyze(metricsText, alertThreshold)
		}
	}

	snapshot := traefikinfra.ToSnapshot(raw, pulseAlerts, traefikOK)
	report   := auditor.Audit(snapshot)

	// Overlay AI router reasoning from the background worker's last run.
	if latestInsights != nil {
		for i, ra := range report.RouterAudits {
			if ri, ok := latestInsights.RouterInsights[ra.Router.Name]; ok {
				report.RouterAudits[i].AIReasoning = ri.Analysis
			}
		}
		resp.AIInsights = toAIInsightsDTO(latestInsights)
	}

	resp.OverallScore = report.OverallScore
	resp.RedFlags     = toRouterAuditDTOs(report.RouterAudits)
	resp.PulseAlerts  = toPulseAlertDTOs(report.PulseAlerts)

	return resp
}

// ── DTO converters ────────────────────────────────────────────────────────

func toRouterAuditDTOs(audits []domain.RouterAudit) []routerAuditDTO {
	out := make([]routerAuditDTO, 0, len(audits))
	for _, a := range audits {
		dto := routerAuditDTO{
			RouterName:  a.Router.Name,
			Rule:        a.Router.Rule,
			Provider:    a.Router.Provider,
			Score:       a.Score,
			IsRedirect:  a.Router.IsRedirect,
			AIReasoning: a.AIReasoning,
			Issues:      make([]issueDTO, 0, len(a.Issues)),
		}
		for _, issue := range a.Issues {
			dto.Issues = append(dto.Issues, issueDTO{
				Code:        issue.Code,
				Description: issue.Description,
				Severity:    issue.Severity.String(),
				AIReasoning: issue.AIReasoning,
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

func toAIInsightsDTO(ai *domain.AIInsights) *aiInsightsDTO {
	dto := &aiInsightsDTO{
		Thought:          ai.Thought,
		Summary:          ai.Summary,
		Severity:         ai.Severity,
		Correlations:     ai.Correlations,
		PromptTokens:     ai.PromptTokens,
		CompletionTokens: ai.CompletionTokens,
		TokensUsed:       ai.TokensUsed,
		LatencyMs:        ai.LatencyMs,
		GeneratedAt:      ai.GeneratedAt,
		Fallback:         ai.Fallback,
	}
	if len(ai.RouterInsights) > 0 {
		dto.RouterInsights = make(map[string]routerInsightDTO, len(ai.RouterInsights))
		for name, ri := range ai.RouterInsights {
			dto.RouterInsights[name] = routerInsightDTO{
				Analysis:      ri.Analysis,
				AttackSurface: ri.AttackSurface,
				Severity:      ri.Severity,
				Remediation:   ri.Remediation,
			}
		}
	}
	for _, s := range ai.ShadowAPIs {
		dto.ShadowAPIs = append(dto.ShadowAPIs, shadowAPIDTO{RouterName: s.RouterName, Reason: s.Reason})
	}
	for _, a := range ai.AggressivityAlerts {
		dto.AggressivityAlerts = append(dto.AggressivityAlerts, aggressivityDTO{
			ServiceName: a.ServiceName,
			Assessment:  a.Assessment,
			Reasoning:   a.Reasoning,
		})
	}
	return dto
}

// ── Config ────────────────────────────────────────────────────────────────

func loadConfig() config {
	cfg := config{
		TraefikURL:       getEnv("TRAEFIK_API_URL", "http://traefik:8080"),
		Port:             getEnv("JANUS_PORT", "9090"),
		AlertThreshold:   0.10,
		VLLMURL:          getEnv("VLLM_API_URL", ""),
		VLLMModel:        getEnv("VLLM_MODEL", "qwen2.5-7b-instruct"),
		VLLMAPIKey:       getEnv("VLLM_API_KEY", ""),
		AIAuditInterval:  60 * time.Second,
		JanusEnv:         getEnv("JANUS_ENV", "production"),
		KnownMiddlewares: getEnv("JANUS_KNOWN_MIDDLEWARES", ""),
		AITracePath:      getEnv("JANUS_AI_TRACE_PATH", "/logs/ai_audit_trace.json"),
	}
	if v := os.Getenv("JANUS_ALERT_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			cfg.AlertThreshold = f
		}
	}
	if v := os.Getenv("JANUS_AI_INTERVAL"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 10 {
			cfg.AIAuditInterval = time.Duration(secs) * time.Second
		}
	}
	cfg.VLLMEnabled = cfg.VLLMURL != ""
	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
