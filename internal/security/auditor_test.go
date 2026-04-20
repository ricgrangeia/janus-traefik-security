package security

import (
	"testing"

	"github.com/janus-project/janus/domain"
)

func snapshotWith(routers []domain.Router, mws map[string]domain.MiddlewareDescriptor) domain.NetworkSnapshot {
	return domain.NetworkSnapshot{
		Routers:     routers,
		Middlewares: mws,
		TraefikOK:   true,
	}
}

func TestAudit_CleanRouter(t *testing.T) {
	r := domain.Router{
		Name:        "api",
		Provider:    "docker",
		IsHTTPS:     true,
		HasTLS:      true,
		Middlewares: []string{"auth@docker", "rl@docker", "ipal@docker"},
	}
	mws := map[string]domain.MiddlewareDescriptor{
		"auth@docker": {Name: "auth", Type: domain.MiddlewareAuth, Provider: "docker"},
		"rl@docker":   {Name: "rl", Type: domain.MiddlewareRateLimit, Provider: "docker"},
		"ipal@docker": {Name: "ipal", Type: domain.MiddlewareIPAllowlist, Provider: "docker"},
	}
	rep := NewAuditor().Audit(snapshotWith([]domain.Router{r}, mws))
	if rep.OverallScore != 100 {
		t.Fatalf("want 100, got %d", rep.OverallScore)
	}
	if !rep.RouterAudits[0].IsClean() {
		t.Fatalf("expected clean router")
	}
}

func TestAudit_MissingAllOnHTTPS(t *testing.T) {
	r := domain.Router{Name: "public", IsHTTPS: true, HasTLS: false}
	rep := NewAuditor().Audit(snapshotWith([]domain.Router{r}, nil))
	// No auth (-40) + no TLS (-30) + no rate limit (-20) + no ip allowlist (-10) = 0
	if rep.OverallScore != 0 {
		t.Fatalf("want 0, got %d", rep.OverallScore)
	}
	if len(rep.RouterAudits[0].Issues) != 4 {
		t.Fatalf("want 4 issues, got %d", len(rep.RouterAudits[0].Issues))
	}
}

func TestAudit_RedirectRouterExcludedFromScore(t *testing.T) {
	redirect := domain.Router{Name: "redir", IsRedirect: true}
	insecure := domain.Router{Name: "bad", IsHTTPS: true}
	rep := NewAuditor().Audit(snapshotWith([]domain.Router{redirect, insecure}, nil))
	// Only 'insecure' counts toward the score.
	if rep.OverallScore != 0 {
		t.Fatalf("want 0 (only insecure counted), got %d", rep.OverallScore)
	}
	if len(rep.RouterAudits) != 2 {
		t.Fatalf("want both audits in report")
	}
}

func TestAudit_NoTLSOnlyWhenHTTPSRequired(t *testing.T) {
	httpRouter := domain.Router{
		Name:        "internal",
		IsHTTPS:     false, // HTTP entrypoint — TLS not required
		Middlewares: []string{"auth@docker", "rl@docker", "ipal@docker"},
	}
	mws := map[string]domain.MiddlewareDescriptor{
		"auth@docker": {Type: domain.MiddlewareAuth},
		"rl@docker":   {Type: domain.MiddlewareRateLimit},
		"ipal@docker": {Type: domain.MiddlewareIPAllowlist},
	}
	rep := NewAuditor().Audit(snapshotWith([]domain.Router{httpRouter}, mws))
	if !rep.RouterAudits[0].IsClean() {
		t.Fatalf("HTTP router with all middlewares should be clean, got %+v", rep.RouterAudits[0].Issues)
	}
}

func TestAudit_EmptySnapshotScores100(t *testing.T) {
	rep := NewAuditor().Audit(domain.NetworkSnapshot{TraefikOK: true})
	if rep.OverallScore != 100 {
		t.Fatalf("empty snapshot should score 100, got %d", rep.OverallScore)
	}
}
