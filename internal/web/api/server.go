package api

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/janus-project/janus/domain"
	"github.com/janus-project/janus/internal/app"
	"github.com/janus-project/janus/internal/infrastructure/firewall"
	janusLogs "github.com/janus-project/janus/internal/infrastructure/logs"
	"github.com/janus-project/janus/internal/infrastructure/storage"
	traefikinfra "github.com/janus-project/janus/internal/infrastructure/traefik"
	"github.com/janus-project/janus/internal/pulse"
	"github.com/janus-project/janus/internal/web/auth"
)

// Server is the HTTP adapter. It holds only references to collaborators it
// needs to serve requests — it does not own their lifecycle.
type Server struct {
	Client          *traefikinfra.Client
	Auditor         domain.Auditor
	Shield          *firewall.ShieldService
	Whitelist       *app.WhitelistService
	AIWorker        *app.AIAuditWorker
	ReviewWorker    *app.BanReviewWorker
	ConsultSvc      *app.ConsultService
	IntelSvc        *app.ThreatIntelService
	LogTailer       *janusLogs.AccessLogTailer
	TrafficAnalyzer *janusLogs.TrafficAnalyzer
	HistoryRepo     storage.Store
	RichRepo        storage.RichStore
	Policies        []domain.Policy
	StaticFS        fs.FS
	Guard           *auth.Guard

	AlertThreshold float64
	AIEnabled      bool

	reportCache struct {
		mu   sync.RWMutex
		prev *domain.AuditReport
	}
}

// Handler returns the *http.ServeMux with every Janus route registered.
// Public routes: /login.html (static), /api/login, /api/logout, /api/auth/status, /auth (Traefik forwardAuth).
// Everything else is wrapped in the Guard middleware.
func (s *Server) Handler() http.Handler {
	protected := http.NewServeMux()
	protected.Handle("/", http.FileServer(http.FS(s.StaticFS)))
	protected.HandleFunc("/api/status", s.handleStatus)
	protected.HandleFunc("/api/v1/history", s.handleHistory)
	protected.HandleFunc("/api/v1/trend", s.handleTrend)

	protected.HandleFunc("GET /api/v1/shield", s.handleShieldGet)
	protected.HandleFunc("POST /api/v1/shield/block", s.handleShieldBlock)
	protected.HandleFunc("POST /api/v1/shield/unblock", s.handleShieldUnblock)
	protected.HandleFunc("GET /api/v1/shield/admin-whitelist", s.handleAdminWhitelistGet)
	protected.HandleFunc("POST /api/v1/shield/admin-whitelist", s.handleAdminWhitelistAdd)
	protected.HandleFunc("DELETE /api/v1/shield/admin-whitelist", s.handleAdminWhitelistRemove)

	protected.HandleFunc("GET /api/v1/intel/whitelist", s.handleIntelWhitelistGet)
	protected.HandleFunc("POST /api/v1/intel/whitelist", s.handleIntelWhitelistAdd)
	protected.HandleFunc("DELETE /api/v1/intel/whitelist", s.handleIntelWhitelistRemove)
	protected.HandleFunc("GET /api/v1/intel", s.handleIntel)
	protected.HandleFunc("GET /api/v1/intel/ip-activity", s.handleIntelIPActivity)
	protected.HandleFunc("POST /api/v1/intel/analyze", s.handleIntelAnalyze)
	protected.HandleFunc("GET /api/v1/intel/report", s.handleIntelReport)

	protected.HandleFunc("/api/v1/ai/consult", s.handleConsult)
	protected.HandleFunc("/api/v1/ai-insights", s.handleAIInsights)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth", s.handleAuth) // Traefik forwardAuth target — stays public
	mux.Handle("GET /login.html", http.FileServer(http.FS(s.StaticFS)))
	if s.Guard != nil {
		mux.HandleFunc("POST /api/login", s.Guard.HandleLogin)
		mux.HandleFunc("POST /api/logout", s.Guard.HandleLogout)
		mux.HandleFunc("GET /api/auth/status", s.Guard.HandleStatus)
		mux.Handle("/", s.Guard.Middleware(protected))
	} else {
		mux.Handle("/", protected)
	}
	return mux
}

// ── Shared helpers ────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if status != 0 {
		w.WriteHeader(status)
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("encode response", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeIP(r *http.Request) (string, error) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		return "", fmt.Errorf("body must be {\"ip\":\"x.x.x.x\"}")
	}
	return body.IP, nil
}

// extractForwardedIP reads the real client IP from a Traefik forwardAuth request.
func extractForwardedIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// ── /auth (Traefik forwardAuth target) ───────────────────────────────────

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	ip := extractForwardedIP(r)
	if ip != "" && s.Shield.IsBlocked(ip) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ── /api/status ───────────────────────────────────────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var latestInsights *domain.AIInsights
	if s.AIWorker != nil {
		latestInsights = s.AIWorker.LatestInsights()
	}

	s.reportCache.mu.RLock()
	prev := s.reportCache.prev
	s.reportCache.mu.RUnlock()

	resp, curr := s.buildStatus(latestInsights, prev)

	s.reportCache.mu.Lock()
	s.reportCache.prev = &curr
	s.reportCache.mu.Unlock()

	writeJSON(w, 0, resp)
}

func (s *Server) buildStatus(
	latestInsights *domain.AIInsights,
	prevReport *domain.AuditReport,
) (StatusResponse, domain.AuditReport) {
	resp := StatusResponse{
		Timestamp:   time.Now().UTC(),
		RedFlags:    []RouterAuditDTO{},
		PulseAlerts: []PulseAlertDTO{},
		AIEnabled:   s.AIEnabled,
	}

	traefikOK := s.Client.Ping()
	resp.TraefikOK = traefikOK
	if !traefikOK {
		resp.Error = "cannot reach Traefik API — is it running?"
		return resp, domain.AuditReport{}
	}

	overview, err := s.Client.FetchOverview()
	if err != nil {
		slog.Warn("fetch overview failed", "err", err)
	} else if overview != nil {
		resp.Overview = ToOverviewDTO(overview)
	}

	raw, err := s.Client.FetchRawData()
	if err != nil {
		resp.Error = fmt.Sprintf("rawdata: %v", err)
		return resp, domain.AuditReport{}
	}

	var pulseAlerts []domain.PulseAlert
	metricsEnabled := overview != nil && overview.Features.Metrics != ""
	resp.MetricsEnabled = metricsEnabled
	if metricsEnabled {
		if metricsText, err := s.Client.FetchMetrics(); err == nil {
			pulseAlerts = pulse.Analyze(metricsText, s.AlertThreshold)
		}
	}

	snapshot := traefikinfra.ToSnapshot(raw, pulseAlerts, traefikOK)
	report := s.Auditor.Audit(snapshot)
	report.GeneratedAt = time.Now().UTC()

	report = app.CheckPolicies(report, snapshot, s.Policies)

	if prevReport != nil {
		drifts := app.DetectDrift(*prevReport, report)
		report.DriftAlerts = drifts
		if len(drifts) > 0 {
			slog.Warn("configuration drift detected", "count", len(drifts))
		}
	}

	if latestInsights != nil {
		for i, ra := range report.RouterAudits {
			if ri, ok := latestInsights.RouterInsights[ra.Router.Name]; ok {
				report.RouterAudits[i].AIReasoning = ri.Analysis
			}
		}
		resp.AIInsights = ToAIInsightsDTO(latestInsights)
	}

	resp.OverallScore = report.OverallScore
	resp.RedFlags = ToRouterAuditDTOs(report.RouterAudits)
	resp.PulseAlerts = ToPulseAlertDTOs(report.PulseAlerts)
	resp.DriftAlerts = ToDriftAlertDTOs(report.DriftAlerts)
	resp.Policies = ToPolicyDTOs(s.Policies)

	return resp, report
}

// ── /api/v1/history & /trend ──────────────────────────────────────────────

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.HistoryRepo == nil {
		writeJSON(w, 0, []struct{}{})
		return
	}
	writeJSON(w, 0, s.HistoryRepo.History())
}

func (s *Server) handleTrend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.RichRepo == nil {
		writeError(w, http.StatusServiceUnavailable, "trend data requires JANUS_DB_PATH to be set")
		return
	}
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 365 {
			days = n
		}
	}
	writeJSON(w, 0, s.RichRepo.GetSecurityTrend(days))
}

// ── /api/v1/shield ────────────────────────────────────────────────────────

type ipActivity struct {
	HitBuckets       []int     `json:"hit_buckets"`
	HitCount30m      int       `json:"hit_count_30m"`
	Verdict          string    `json:"verdict,omitempty"`
	VerdictLabel     string    `json:"verdict_label,omitempty"`
	VerdictReasoning string    `json:"verdict_reasoning,omitempty"`
	ReviewedAt       time.Time `json:"reviewed_at,omitempty"`
}

func (s *Server) handleShieldGet(w http.ResponseWriter, _ *http.Request) {
	ips := s.Shield.ListBlocked()
	if ips == nil {
		ips = []string{}
	}

	activity := make(map[string]ipActivity, len(ips))
	for _, ip := range ips {
		entry := ipActivity{HitBuckets: make([]int, 6)}
		if s.LogTailer != nil {
			buckets := s.LogTailer.BucketHits(ip, 6, 300)
			total := 0
			for _, b := range buckets {
				total += b
			}
			entry.HitBuckets = buckets
			entry.HitCount30m = total
		}
		if s.ReviewWorker != nil {
			if v, ok := s.ReviewWorker.GetVerdict(ip); ok {
				entry.Verdict = v.Verdict
				entry.VerdictLabel = v.Label
				entry.VerdictReasoning = v.Reasoning
				entry.ReviewedAt = v.ReviewedAt
			}
		}
		activity[ip] = entry
	}

	adminList := s.Shield.GetAdminWhitelist()
	if adminList == nil {
		adminList = []string{}
	}
	var immuneIPs []string
	if s.Whitelist != nil {
		immuneIPs = s.Whitelist.List()
	}

	writeJSON(w, 0, map[string]any{
		"blocked_ips":     ips,
		"activity":        activity,
		"admin_whitelist": adminList,
		"immune_ips":      immuneIPs,
	})
}

func (s *Server) handleShieldBlock(w http.ResponseWriter, r *http.Request) {
	ip, err := decodeIP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Shield.BlockIP(ip); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("Shield: IP blocked via API", "ip", ip)
	writeJSON(w, 0, map[string]string{"status": "blocked", "ip": ip})
}

func (s *Server) handleShieldUnblock(w http.ResponseWriter, r *http.Request) {
	ip, err := decodeIP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Shield.UnblockIP(ip); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("Shield: IP unblocked via API", "ip", ip)
	writeJSON(w, 0, map[string]string{"status": "unblocked", "ip": ip})
}

func (s *Server) handleAdminWhitelistGet(w http.ResponseWriter, _ *http.Request) {
	ips := s.Shield.GetAdminWhitelist()
	if ips == nil {
		ips = []string{}
	}
	writeJSON(w, 0, ips)
}

func (s *Server) handleAdminWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	ip, err := decodeIP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Shield.AddAdminIP(ip); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Info("Shield: admin whitelist IP added", "ip", ip)
	writeJSON(w, 0, map[string]string{"status": "added", "ip": ip})
}

func (s *Server) handleAdminWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	ip, err := decodeIP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Shield.RemoveAdminIP(ip); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("Shield: admin whitelist IP removed", "ip", ip)
	writeJSON(w, 0, map[string]string{"status": "removed", "ip": ip})
}

// ── /api/v1/intel ─────────────────────────────────────────────────────────

func (s *Server) handleIntelWhitelistGet(w http.ResponseWriter, _ *http.Request) {
	if s.Whitelist == nil {
		writeJSON(w, 0, []string{})
		return
	}
	writeJSON(w, 0, s.Whitelist.List())
}

func (s *Server) handleIntelWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if s.Whitelist == nil {
		writeError(w, http.StatusServiceUnavailable, "whitelist not configured")
		return
	}
	ip, err := decodeIP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Whitelist.Add(ip); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("Intel whitelist: IP trusted", "ip", ip)
	writeJSON(w, 0, map[string]string{"status": "trusted", "ip": ip})
}

func (s *Server) handleIntelWhitelistRemove(w http.ResponseWriter, r *http.Request) {
	if s.Whitelist == nil {
		writeError(w, http.StatusServiceUnavailable, "whitelist not configured")
		return
	}
	ip, err := decodeIP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Whitelist.Remove(ip); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	slog.Info("Intel whitelist: IP untrusted", "ip", ip)
	writeJSON(w, 0, map[string]string{"status": "removed", "ip": ip})
}

func (s *Server) handleIntel(w http.ResponseWriter, _ *http.Request) {
	if s.IntelSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "threat intel requires AI and JANUS_ACCESS_LOG_PATH to be configured")
		return
	}
	report := s.IntelSvc.LatestReport()
	if report == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, 0, report)
}

func (s *Server) handleIntelIPActivity(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip query parameter required")
		return
	}
	if s.TrafficAnalyzer == nil {
		writeError(w, http.StatusServiceUnavailable, "traffic analyzer not configured")
		return
	}
	errors, total4xx, total5xx := s.TrafficAnalyzer.RecentErrors(ip, 50)
	if errors == nil {
		errors = []janusLogs.ErrorSample{}
	}
	writeJSON(w, 0, map[string]any{
		"ip":        ip,
		"total_4xx": total4xx,
		"total_5xx": total5xx,
		"errors":    errors,
	})
}

func (s *Server) handleIntelAnalyze(w http.ResponseWriter, _ *http.Request) {
	if s.IntelSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "threat intel requires AI and JANUS_ACCESS_LOG_PATH to be configured")
		return
	}
	s.IntelSvc.AnalyzeAsync()
	writeJSON(w, 0, map[string]string{"status": "analysis started"})
}

func (s *Server) handleIntelReport(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="janus-threat-report.md"`)
	w.Header().Set("Cache-Control", "no-store")
	md := "# Janus Threat Intelligence Report\n\nNo analysis has been run yet.\n"
	if s.IntelSvc != nil {
		md = s.IntelSvc.MarkdownReport()
	}
	_, _ = w.Write([]byte(md))
}

// ── /api/v1/ai/consult & /ai-insights ────────────────────────────────────

func (s *Server) handleConsult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.ConsultSvc == nil {
		writeError(w, http.StatusServiceUnavailable, "AI or history not configured")
		return
	}
	summary, tokens, err := s.ConsultSvc.ExecutiveSummary()
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, 0, map[string]any{
		"summary":     summary,
		"tokens_used": tokens,
	})
}

func (s *Server) handleAIInsights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.AIWorker == nil {
		writeError(w, http.StatusServiceUnavailable, "AI features disabled — set VLLM_API_URL to enable")
		return
	}
	insights := s.AIWorker.LatestInsights()
	if insights == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, 0, ToAIInsightsDTO(insights))
}
