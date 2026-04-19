package domain

import "time"

// AIInsights holds the global analysis produced by the AI analyst for one audit cycle.
type AIInsights struct {
	Summary            string               // 2-3 sentence overall assessment
	Correlations       []string             // cross-router patterns (e.g. all internal tools lack auth)
	ShadowAPIs         []ShadowAPIAlert     // routes that look like undocumented internal tools
	AggressivityAlerts []AggressivityAlert  // bot scan vs bad code assessment per service
	RouterReasoning    map[string]string    // router name → specific AI recommendation
	TokensUsed         int                  // prompt + completion tokens consumed
	LatencyMs          int64                // round-trip time to vLLM
	GeneratedAt        time.Time
}

// ShadowAPIAlert flags a router that looks like an internal or undocumented API
// exposed without authentication.
type ShadowAPIAlert struct {
	RouterName string
	Reason     string
}

// AggressivityAlert classifies a service's error rate spike.
type AggressivityAlert struct {
	ServiceName string
	Assessment  string // "bot_scan" | "bad_code" | "legitimate_traffic" | "unknown"
	Reasoning   string
}

// AIAnalyst is the domain service interface for AI-powered security analysis.
// It takes a completed AuditReport and the raw NetworkSnapshot, and returns
// an enriched report with AI-generated insights.
// Implementations live in /internal/infrastructure/llm.
// Janus continues to function with basic gap reporting if the AI is offline.
type AIAnalyst interface {
	Analyze(report AuditReport, snapshot NetworkSnapshot) (AuditReport, error)
}
