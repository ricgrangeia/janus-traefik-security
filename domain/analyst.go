package domain

import "time"

// RouterInsight holds AI-generated deep analysis for a single router.
type RouterInsight struct {
	Analysis      string   // AI's detailed security assessment
	AttackSurface string   // how an external attacker would exploit this configuration
	Severity      int      // 0-10 severity score for this router
	Remediation   []string // specific Traefik labels/config the developer should add
}

// AIInsights holds the global analysis produced by the AI analyst for one audit cycle.
type AIInsights struct {
	Thought            string                     // chain-of-thought reasoning block (Janus-AI internal)
	Summary            string                     // 2-3 sentence overall assessment
	Severity           int                        // 0-10 overall severity score
	Correlations       []string                   // cross-router patterns indicating systemic failures
	ShadowAPIs         []ShadowAPIAlert           // routes that look like undocumented internal tools
	AggressivityAlerts []AggressivityAlert         // bot scan vs bad code assessment per service
	RouterInsights     map[string]RouterInsight    // router name → detailed AI insight
	PromptTokens       int                        // input tokens consumed
	CompletionTokens   int                        // output tokens consumed
	TokensUsed         int                        // total tokens (prompt + completion)
	LatencyMs          int64                      // round-trip time to vLLM
	GeneratedAt        time.Time
	Fallback           bool // true when AI was unavailable and heuristics were used
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
	SuspectedIP string // optional: IP the AI identified as the likely attacker
}

// AIAnalyst is the domain service interface for AI-powered security analysis.
// It takes a completed AuditReport and the raw NetworkSnapshot, and returns
// an enriched report with AI-generated insights.
// Implementations live in /internal/infrastructure/llm.
// Janus continues to function with basic gap reporting if the AI is offline.
type AIAnalyst interface {
	Analyze(report AuditReport, snapshot NetworkSnapshot) (AuditReport, error)
}
