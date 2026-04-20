package domain

import "time"

// RouterAudit holds the security audit result for a single router.
// It is a component of the AuditReport aggregate — it has no identity of its own.
type RouterAudit struct {
	Router           Router
	Issues           []SecurityIssue
	PolicyViolations []PolicyViolation // violations of user-defined policies
	Score            int               // 0 (critical) – 100 (clean)
	AIReasoning      string            // per-router insight from the AI analyst; empty until first AI run
}

// IsClean returns true when no security issues and no policy violations were detected.
func (ra RouterAudit) IsClean() bool {
	return len(ra.Issues) == 0 && len(ra.PolicyViolations) == 0
}

// PulseAlert represents a service whose combined 4xx+5xx error rate
// exceeds the configured alert threshold.
type PulseAlert struct {
	ServiceName string
	Total       float64
	Count4xx    float64
	Count5xx    float64
	ErrorRate   float64 // 0.0–1.0
}

// AuditReport is the Aggregate Root produced by the Auditor domain service.
// It represents a complete, point-in-time security assessment of the Traefik network.
// AIInsights is populated asynchronously — it is nil until the first AI audit completes.
type AuditReport struct {
	GeneratedAt  time.Time
	TraefikOK    bool
	RouterAudits []RouterAudit
	PulseAlerts  []PulseAlert
	DriftAlerts  []DriftAlert  // set when security posture regressed since last audit
	OverallScore int
	AIInsights   *AIInsights
	Error        string
}

// RedFlagRouters returns router audits that have at least one security issue,
// excluding redirect routers which are infrastructure by design.
func (ar AuditReport) RedFlagRouters() []RouterAudit {
	var out []RouterAudit
	for _, ra := range ar.RouterAudits {
		if !ra.Router.IsRedirect && !ra.IsClean() {
			out = append(out, ra)
		}
	}
	return out
}

// CleanRouters returns router audits with no security issues (non-redirect only).
func (ar AuditReport) CleanRouters() []RouterAudit {
	var out []RouterAudit
	for _, ra := range ar.RouterAudits {
		if !ra.Router.IsRedirect && ra.IsClean() {
			out = append(out, ra)
		}
	}
	return out
}

// RedirectRouters returns the HTTP→HTTPS redirect routers, which are
// excluded from the overall score.
func (ar AuditReport) RedirectRouters() []RouterAudit {
	var out []RouterAudit
	for _, ra := range ar.RouterAudits {
		if ra.Router.IsRedirect {
			out = append(out, ra)
		}
	}
	return out
}
