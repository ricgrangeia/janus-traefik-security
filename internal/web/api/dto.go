// Package api exposes Janus's HTTP/JSON surface. All JSON tags live here — the
// domain layer is kept pure. Handlers convert domain values into DTOs before
// encoding. This is the Anti-Corruption Layer between HTTP and the domain.
package api

import (
	"time"

	"github.com/janus-project/janus/domain"
)

type StatusResponse struct {
	Timestamp      time.Time        `json:"timestamp"`
	TraefikOK      bool             `json:"traefik_ok"`
	OverallScore   int              `json:"overall_score"`
	RedFlags       []RouterAuditDTO `json:"red_flags"`
	PulseAlerts    []PulseAlertDTO  `json:"pulse_alerts"`
	MetricsEnabled bool             `json:"metrics_enabled"`
	Overview       *OverviewDTO     `json:"overview,omitempty"`
	AIInsights     *AIInsightsDTO   `json:"ai_insights,omitempty"`
	AIEnabled      bool             `json:"ai_enabled"`
	Policies       []PolicyDTO      `json:"policies,omitempty"`
	DriftAlerts    []DriftAlertDTO  `json:"drift_alerts,omitempty"`
	Error          string           `json:"error,omitempty"`
}

type OverviewDTO struct {
	HTTP      HTTPStatsDTO `json:"http"`
	Providers []string     `json:"providers"`
}

type HTTPStatsDTO struct {
	Routers     EntityStatsDTO `json:"routers"`
	Services    EntityStatsDTO `json:"services"`
	Middlewares EntityStatsDTO `json:"middlewares"`
}

type EntityStatsDTO struct {
	Total    int `json:"total"`
	Warnings int `json:"warnings"`
	Errors   int `json:"errors"`
}

type RouterAuditDTO struct {
	RouterName         string               `json:"router_name"`
	Rule               string               `json:"rule"`
	Provider           string               `json:"provider"`
	Issues             []IssueDTO           `json:"issues"`
	PolicyViolations   []PolicyViolationDTO `json:"policy_violations,omitempty"`
	Score              int                  `json:"score"`
	IsRedirect         bool                 `json:"is_redirect"`
	AIReasoning        string               `json:"ai_reasoning,omitempty"`
	RemediationSnippet string               `json:"remediation_snippet,omitempty"`
}

type PolicyDTO struct {
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	Required    []string `json:"required"`
	Description string   `json:"description"`
}

type PolicyViolationDTO struct {
	PolicyName string   `json:"policy_name"`
	Pattern    string   `json:"pattern"`
	Missing    []string `json:"missing"`
}

type DriftAlertDTO struct {
	RouterName string   `json:"router_name"`
	LostChecks []string `json:"lost_checks"`
	OldScore   int      `json:"old_score"`
	NewScore   int      `json:"new_score"`
}

type IssueDTO struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	AIReasoning string `json:"ai_reasoning,omitempty"`
}

type PulseAlertDTO struct {
	ServiceName string  `json:"service_name"`
	Total       float64 `json:"total_requests"`
	Count4xx    float64 `json:"count_4xx"`
	Count5xx    float64 `json:"count_5xx"`
	ErrorRate   float64 `json:"error_rate"`
}

type AIInsightsDTO struct {
	Thought            string                      `json:"thought,omitempty"`
	Summary            string                      `json:"summary"`
	Severity           int                         `json:"severity"`
	Correlations       []string                    `json:"correlations"`
	ShadowAPIs         []ShadowAPIDTO              `json:"shadow_apis"`
	AggressivityAlerts []AggressivityDTO           `json:"aggressivity_alerts"`
	RouterInsights     map[string]RouterInsightDTO `json:"router_insights,omitempty"`
	PromptTokens       int                         `json:"prompt_tokens"`
	CompletionTokens   int                         `json:"completion_tokens"`
	TokensUsed         int                         `json:"tokens_used"`
	LatencyMs          int64                       `json:"latency_ms"`
	GeneratedAt        time.Time                   `json:"generated_at"`
	Fallback           bool                        `json:"fallback"`
}

type ShadowAPIDTO struct {
	RouterName string `json:"router_name"`
	Reason     string `json:"reason"`
}

type AggressivityDTO struct {
	ServiceName string `json:"service_name"`
	Assessment  string `json:"assessment"`
	Reasoning   string `json:"reasoning"`
	SuspectedIP string `json:"suspected_ip,omitempty"`
}

type RouterInsightDTO struct {
	Analysis      string   `json:"analysis"`
	AttackSurface string   `json:"attack_surface"`
	Severity      int      `json:"severity"`
	Remediation   []string `json:"remediation"`
}

// Assert compile-time use of domain — we intentionally import domain so this
// package is co-located with its source of truth (the domain types it mirrors).
var _ = domain.SeverityLow
