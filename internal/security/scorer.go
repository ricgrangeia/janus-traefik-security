package security

import (
	"strings"

	"github.com/janus-project/janus/internal/traefik"
)

// authMiddlewareTypes are Traefik middleware types that enforce authentication.
var authMiddlewareTypes = map[string]bool{
	"basicauth":   true,
	"digestauth":  true,
	"forwardauth": true,
}

// secureEntrypoints are entrypoint names that are expected to carry TLS.
var secureEntrypoints = map[string]bool{
	"websecure": true,
	"https":     true,
	"443":       true,
}

// RedFlag describes a router with security issues.
type RedFlag struct {
	RouterName  string   `json:"router_name"`
	Rule        string   `json:"rule"`
	Provider    string   `json:"provider"`
	Issues      []string `json:"issues"`
	Score       int      `json:"score"`       // 0 (critical) – 100 (clean)
	IsRedirect  bool     `json:"is_redirect"` // true = HTTP→HTTPS redirect router, scoring skipped
}

// Analyze scans all routers and returns per-router red flags plus an
// overall score (0–100). Internal and redirect-only routers are excluded
// from the overall score — they are infrastructure, not service endpoints.
func Analyze(data *traefik.RawData) ([]RedFlag, int) {
	var flags []RedFlag
	totalScore := 0
	scoredCount := 0

	for name, router := range data.Routers {
		if strings.HasSuffix(name, "@internal") {
			continue
		}

		flag := scoreRouter(name, router, data.Middlewares)
		flags = append(flags, flag)

		// Redirect routers are shown in the UI but don't pollute the overall score.
		if !flag.IsRedirect {
			totalScore += flag.Score
			scoredCount++
		}
	}

	overall := 100
	if scoredCount > 0 {
		overall = totalScore / scoredCount
	}

	return flags, overall
}

func scoreRouter(name string, r traefik.Router, middlewares map[string]traefik.Middleware) RedFlag {
	flag := RedFlag{
		RouterName: name,
		Rule:       r.Rule,
		Provider:   r.Provider,
		Score:      100,
	}

	// A router whose only job is redirecting HTTP→HTTPS is infrastructure.
	// It has no TLS by design and needs no auth — skip security scoring.
	if isRedirectRouter(r, middlewares) {
		flag.IsRedirect = true
		return flag
	}

	// ── TLS check ──────────────────────────────────────────────────────────
	// Only flag TLS absence on routers bound to a secure entrypoint (websecure).
	// Routers on the plain `web` entrypoint are not expected to carry TLS.
	if isSecureEntrypoint(r.EntryPoints) && r.TLS == nil {
		flag.Issues = append(flag.Issues, "No TLS configured on secure entrypoint (websecure)")
		flag.Score -= 30
	}

	// ── Auth middleware check ───────────────────────────────────────────────
	if !hasMiddlewareOfType(r.Middlewares, middlewares, authMiddlewareTypes) {
		flag.Issues = append(flag.Issues, "No authentication middleware (basicAuth / forwardAuth / digestAuth)")
		flag.Score -= 40
	}

	// ── Rate limiting check ─────────────────────────────────────────────────
	if !hasMiddlewareOfType(r.Middlewares, middlewares, map[string]bool{"ratelimit": true}) {
		flag.Issues = append(flag.Issues, "No rate limiting middleware")
		flag.Score -= 20
	}

	// ── IP allowlist check ──────────────────────────────────────────────────
	if !hasMiddlewareOfType(r.Middlewares, middlewares, map[string]bool{
		"ipallowlist": true,
		"ipwhitelist": true, // Traefik v2 legacy name
	}) {
		flag.Issues = append(flag.Issues, "No IP allowlist middleware")
		flag.Score -= 10
	}

	if flag.Score < 0 {
		flag.Score = 0
	}

	return flag
}

// isRedirectRouter returns true when every middleware on the router is a
// redirectscheme — meaning the router's sole purpose is HTTP→HTTPS redirection.
func isRedirectRouter(r traefik.Router, middlewares map[string]traefik.Middleware) bool {
	if len(r.Middlewares) == 0 {
		return false
	}
	for _, ref := range r.Middlewares {
		mw, ok := resolveMiddleware(ref, middlewares)
		if !ok || strings.ToLower(mw.Type) != "redirectscheme" {
			return false
		}
	}
	return true
}

// isSecureEntrypoint returns true when the router is bound to an entrypoint
// that is expected to carry TLS (websecure / https / 443).
func isSecureEntrypoint(eps []string) bool {
	for _, ep := range eps {
		if secureEntrypoints[strings.ToLower(ep)] {
			return true
		}
	}
	return false
}

// hasMiddlewareOfType checks whether the router's middleware list contains
// at least one middleware whose type is in the target set.
func hasMiddlewareOfType(refs []string, all map[string]traefik.Middleware, types map[string]bool) bool {
	for _, ref := range refs {
		mw, ok := resolveMiddleware(ref, all)
		if !ok {
			continue
		}
		if types[strings.ToLower(mw.Type)] {
			return true
		}
	}
	return false
}

// resolveMiddleware looks up a middleware by its router reference name,
// handling cases where the @provider suffix may be absent.
func resolveMiddleware(ref string, all map[string]traefik.Middleware) (traefik.Middleware, bool) {
	if mw, ok := all[ref]; ok {
		return mw, true
	}
	base := strings.SplitN(ref, "@", 2)[0]
	for key, mw := range all {
		if strings.SplitN(key, "@", 2)[0] == base {
			return mw, true
		}
	}
	return traefik.Middleware{}, false
}
