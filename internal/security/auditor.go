package security

import (
	"github.com/janus-project/janus/domain"
)

// SecurityAuditor implements domain.Auditor.
// It applies the Janus security ruleset to a NetworkSnapshot and
// produces a fully-scored AuditReport.
type SecurityAuditor struct{}

func NewAuditor() domain.Auditor {
	return SecurityAuditor{}
}

// Audit iterates every router in the snapshot, applies the security ruleset,
// and assembles an AuditReport. Redirect routers are included in the report
// but excluded from the overall score calculation.
func (a SecurityAuditor) Audit(snapshot domain.NetworkSnapshot) domain.AuditReport {
	report := domain.AuditReport{
		TraefikOK:   snapshot.TraefikOK,
		PulseAlerts: snapshot.PulseAlerts,
	}

	totalScore := 0
	scoredCount := 0

	for _, router := range snapshot.Routers {
		audit := auditRouter(router, snapshot)
		report.RouterAudits = append(report.RouterAudits, audit)

		if !router.IsRedirect {
			totalScore += audit.Score
			scoredCount++
		}
	}

	report.OverallScore = 100
	if scoredCount > 0 {
		report.OverallScore = totalScore / scoredCount
	}

	return report
}

// auditRouter applies all security rules to a single router and returns
// its RouterAudit with a computed score.
func auditRouter(r domain.Router, snapshot domain.NetworkSnapshot) domain.RouterAudit {
	audit := domain.RouterAudit{
		Router: r,
		Score:  100,
	}

	// Redirect routers are infrastructure — no security rules apply.
	if r.IsRedirect {
		return audit
	}

	rules := []func(domain.Router, domain.NetworkSnapshot) *domain.SecurityIssue{
		checkTLS,
		checkAuth,
		checkRateLimit,
		checkIPAllowlist,
	}

	for _, rule := range rules {
		if issue := rule(r, snapshot); issue != nil {
			audit.Issues = append(audit.Issues, *issue)
			audit.Score -= issue.Severity.ScoreDeduction()
		}
	}

	if audit.Score < 0 {
		audit.Score = 0
	}

	return audit
}

// ── Security rules ────────────────────────────────────────────────────────
// Each rule returns a *SecurityIssue if the check fails, nil if it passes.

func checkTLS(r domain.Router, _ domain.NetworkSnapshot) *domain.SecurityIssue {
	if r.RequiresTLSAudit() && !r.HasTLS {
		issue := domain.IssueNoTLS
		return &issue
	}
	return nil
}

func checkAuth(r domain.Router, s domain.NetworkSnapshot) *domain.SecurityIssue {
	if !s.HasMiddlewareType(r, domain.MiddlewareAuth) {
		issue := domain.IssueNoAuth
		return &issue
	}
	return nil
}

func checkRateLimit(r domain.Router, s domain.NetworkSnapshot) *domain.SecurityIssue {
	if !s.HasMiddlewareType(r, domain.MiddlewareRateLimit) {
		issue := domain.IssueNoRateLimit
		return &issue
	}
	return nil
}

func checkIPAllowlist(r domain.Router, s domain.NetworkSnapshot) *domain.SecurityIssue {
	if !s.HasMiddlewareType(r, domain.MiddlewareIPAllowlist) {
		issue := domain.IssueNoIPAllowlist
		return &issue
	}
	return nil
}
