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
	"sync"
	"time"

	"github.com/janus-project/janus/domain"
	"github.com/janus-project/janus/internal/app"
	traefikinfra "github.com/janus-project/janus/internal/infrastructure/traefik"
	"github.com/janus-project/janus/internal/infrastructure/llm"
	"github.com/janus-project/janus/internal/infrastructure/storage"
	"github.com/janus-project/janus/internal/infrastructure/telegram"
	"github.com/janus-project/janus/internal/pulse"
	"github.com/janus-project/janus/internal/security"
	janusWeb "github.com/janus-project/janus/internal/web"
)

// config holds all runtime configuration sourced from environment variables.
type config struct {
	TraefikURL        string
	Port              string
	AlertThreshold    float64
	VLLMEnabled       bool
	VLLMURL           string
	VLLMModel         string
	VLLMAPIKey        string
	AIAuditInterval   time.Duration
	JanusEnv          string
	KnownMiddlewares  string // raw CSV, parsed before use
	AITracePath       string
	HistoryPath       string
	TelegramToken     string
	TelegramChatID    string
	ThreatSeverityMin int
	PoliciesPath      string
	DBPath            string
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
	Policies       []policyDTO      `json:"policies,omitempty"`
	DriftAlerts    []driftAlertDTO  `json:"drift_alerts,omitempty"`
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
	RouterName          string               `json:"router_name"`
	Rule                string               `json:"rule"`
	Provider            string               `json:"provider"`
	Issues              []issueDTO           `json:"issues"`
	PolicyViolations    []policyViolationDTO `json:"policy_violations,omitempty"`
	Score               int                  `json:"score"`
	IsRedirect          bool                 `json:"is_redirect"`
	AIReasoning         string               `json:"ai_reasoning,omitempty"`
	RemediationSnippet  string               `json:"remediation_snippet,omitempty"`
}

type policyDTO struct {
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	Required    []string `json:"required"`
	Description string   `json:"description"`
}

type policyViolationDTO struct {
	PolicyName string   `json:"policy_name"`
	Pattern    string   `json:"pattern"`
	Missing    []string `json:"missing"`
}

type driftAlertDTO struct {
	RouterName string   `json:"router_name"`
	LostChecks []string `json:"lost_checks"`
	OldScore   int      `json:"old_score"`
	NewScore   int      `json:"new_score"`
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
		"telegram_enabled", cfg.TelegramToken != "",
	)

	client  := traefikinfra.NewClient(cfg.TraefikURL)
	auditor := security.NewAuditor()

	// ── Policies ──────────────────────────────────────────────────────────
	policies, err := app.LoadPolicies(cfg.PoliciesPath)
	if err != nil {
		log.Fatalf("load policies: %v", err)
	}

	// ── History / persistence (SQLite preferred, JSON fallback) ─────────────
	var historyRepo storage.Store
	var richRepo    storage.RichStore
	if cfg.DBPath != "" {
		r, err := storage.NewSQLiteRepository(cfg.DBPath)
		if err != nil {
			log.Fatalf("open SQLite database: %v", err)
		}
		historyRepo = r
		richRepo    = r
	} else if cfg.HistoryPath != "" {
		historyRepo = storage.NewRepository(cfg.HistoryPath)
	}
	_ = richRepo // used by /api/v1/trend handler below

	// ── Previous-report cache for drift detection ─────────────────────────
	var reportCache struct {
		mu   sync.RWMutex
		prev *domain.AuditReport
	}

	// ── Optional AI worker + consult service ─────────────────────────────
	var aiWorker     *app.AIAuditWorker
	var consultSvc   *app.ConsultService
	var llmClient    *llm.Client
	if cfg.VLLMEnabled {
		knownMiddlewares := app.ParseKnownMiddlewares(cfg.KnownMiddlewares)
		llmClient         = llm.NewClient(cfg.VLLMURL, cfg.VLLMModel, cfg.VLLMAPIKey)
		analyst           := llm.NewAnalyst(llmClient, cfg.JanusEnv, knownMiddlewares)
		aiWorker           = app.NewAIAuditWorker(
			client, auditor, analyst,
			cfg.AlertThreshold, cfg.AIAuditInterval, cfg.AITracePath,
		)
		if historyRepo != nil {
			aiWorker.WithStorage(historyRepo)
			consultSvc = app.NewConsultService(llmClient, historyRepo)
		}
		if cfg.TelegramToken != "" {
			notifier := telegram.NewNotifier(cfg.TelegramToken, cfg.TelegramChatID)
			aiWorker.WithNotifier(notifier, cfg.ThreatSeverityMin)
		}
		ctx, cancel := context.WithCancel(context.Background())
		_ = cancel
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

		reportCache.mu.RLock()
		prev := reportCache.prev
		reportCache.mu.RUnlock()

		resp, curr := buildStatus(client, auditor, cfg.AlertThreshold, cfg.VLLMEnabled, latestInsights, policies, prev)

		reportCache.mu.Lock()
		reportCache.prev = &curr
		reportCache.mu.Unlock()

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			slog.Error("encode status response", "err", err)
		}
	})

	// GET /api/v1/history — returns audit summaries for trend analysis.
	mux.HandleFunc("/api/v1/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		if historyRepo == nil {
			_ = json.NewEncoder(w).Encode([]struct{}{})
			return
		}
		if err := json.NewEncoder(w).Encode(historyRepo.History()); err != nil {
			slog.Error("encode history response", "err", err)
		}
	})

	// GET /api/v1/trend — last 30-day score trend (SQLite only).
	mux.HandleFunc("/api/v1/trend", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		if richRepo == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "trend data requires JANUS_DB_PATH to be set"})
			return
		}
		days := 30
		if v := r.URL.Query().Get("days"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 365 {
				days = n
			}
		}
		if err := json.NewEncoder(w).Encode(richRepo.GetSecurityTrend(days)); err != nil {
			slog.Error("encode trend response", "err", err)
		}
	})

	// GET /api/v1/ai/consult — on-demand executive summary over audit history.
	mux.HandleFunc("/api/v1/ai/consult", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")

		if consultSvc == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "AI or history not configured"})
			return
		}
		summary, tokens, err := consultSvc.ExecutiveSummary()
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"summary":     summary,
			"tokens_used": tokens,
		})
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

// buildStatus runs the synchronous security audit, applies policies and drift
// detection, overlays AI insights, and returns both the HTTP response DTO and
// the raw AuditReport (for caching as the next call's prevReport).
func buildStatus(
	client *traefikinfra.Client,
	auditor domain.Auditor,
	alertThreshold float64,
	aiEnabled bool,
	latestInsights *domain.AIInsights,
	policies []domain.Policy,
	prevReport *domain.AuditReport,
) (statusResponse, domain.AuditReport) {
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
		return resp, domain.AuditReport{}
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
		return resp, domain.AuditReport{}
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
	report.GeneratedAt = time.Now().UTC()

	// Apply user-defined policies.
	report = app.CheckPolicies(report, snapshot, policies)

	// Detect configuration drift against the previous audit.
	if prevReport != nil {
		drifts := app.DetectDrift(*prevReport, report)
		report.DriftAlerts = drifts
		if len(drifts) > 0 {
			slog.Warn("configuration drift detected", "count", len(drifts))
		}
	}

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
	resp.DriftAlerts  = toDriftAlertDTOs(report.DriftAlerts)
	resp.Policies     = toPolicyDTOs(policies)

	return resp, report
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
		if !a.IsClean() && !a.Router.IsRedirect {
			dto.RemediationSnippet = app.FormatDockerLabels(a.Router.Name, a.Issues, nil)
		}
		for _, pv := range a.PolicyViolations {
			missing := make([]string, len(pv.Missing))
			for i, m := range pv.Missing {
				missing[i] = string(m)
			}
			dto.PolicyViolations = append(dto.PolicyViolations, policyViolationDTO{
				PolicyName: pv.PolicyName,
				Pattern:    pv.Pattern,
				Missing:    missing,
			})
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

func toDriftAlertDTOs(alerts []domain.DriftAlert) []driftAlertDTO {
	out := make([]driftAlertDTO, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, driftAlertDTO{
			RouterName: a.RouterName,
			LostChecks: a.LostChecks,
			OldScore:   a.OldScore,
			NewScore:   a.NewScore,
		})
	}
	return out
}

func toPolicyDTOs(policies []domain.Policy) []policyDTO {
	out := make([]policyDTO, 0, len(policies))
	for _, p := range policies {
		req := make([]string, len(p.Required))
		for i, r := range p.Required {
			req[i] = string(r)
		}
		out = append(out, policyDTO{
			Name:        p.Name,
			Pattern:     p.Pattern,
			Required:    req,
			Description: p.Description,
		})
	}
	return out
}

// ── Config ────────────────────────────────────────────────────────────────

func loadConfig() config {
	cfg := config{
		TraefikURL:        getEnv("TRAEFIK_API_URL", "http://traefik:8080"),
		Port:              getEnv("JANUS_PORT", "9090"),
		AlertThreshold:    0.10,
		VLLMURL:           getEnv("VLLM_API_URL", ""),
		VLLMModel:         getEnv("VLLM_MODEL", "qwen2.5-7b-instruct"),
		VLLMAPIKey:        getEnv("VLLM_API_KEY", ""),
		AIAuditInterval:   60 * time.Second,
		JanusEnv:          getEnv("JANUS_ENV", "production"),
		KnownMiddlewares:  getEnv("JANUS_KNOWN_MIDDLEWARES", ""),
		AITracePath:       getEnv("JANUS_AI_TRACE_PATH", "/logs/ai_audit_trace.json"),
		HistoryPath:       getEnv("JANUS_HISTORY_PATH", "/logs/audit_history.json"),
		TelegramToken:     getEnv("TELEGRAM_BOT_TOKEN", ""),
		TelegramChatID:    getEnv("TELEGRAM_CHAT_ID", ""),
		ThreatSeverityMin: 8,
		PoliciesPath:      getEnv("JANUS_POLICIES_PATH", "/configs/policies.json"),
		DBPath:            getEnv("JANUS_DB_PATH", "/app/data/janus.db"),
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
	if v := os.Getenv("TELEGRAM_SEVERITY_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10 {
			cfg.ThreatSeverityMin = n
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
