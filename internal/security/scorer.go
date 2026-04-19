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

// RedFlag describes a router with security issues.
type RedFlag struct {
	RouterName string   `json:"router_name"`
	Rule       string   `json:"rule"`
	Provider   string   `json:"provider"`
	Issues     []string `json:"issues"`
	Score      int      `json:"score"` // 0 (critical) – 100 (clean)
}

// Analyze scans all routers and returns per-router red flags plus an
// overall score (0–100). Routers with internal/dashboard providers are
// skipped — they are infrastructure, not user-facing routes.
func Analyze(data *traefik.RawData) ([]RedFlag, int) {
	var flags []RedFlag
	totalScore := 0

	for name, router := range data.Routers {
		// Skip Traefik's own internal routers.
		if strings.HasSuffix(name, "@internal") {
			continue
		}

		flag := scoreRouter(name, router, data.Middlewares)
		flags = append(flags, flag)
		totalScore += flag.Score
	}

	overall := 100
	if len(flags) > 0 {
		overall = totalScore / len(flags)
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

	onPublicEntrypoint := isPublicEntrypoint(r.EntryPoints)

	// ── TLS check ──────────────────────────────────────────────────────────
	// A router on a "secure" entrypoint should always have TLS configured.
	if onPublicEntrypoint && r.TLS == nil {
		flag.Issues = append(flag.Issues, "No TLS configured on public entrypoint")
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

// isPublicEntrypoint returns true when any entrypoint name suggests a
// publicly-reachable port (web, websecure, https, 443, etc.).
func isPublicEntrypoint(eps []string) bool {
	public := map[string]bool{
		"web": true, "websecure": true, "https": true, "http": true,
	}
	for _, ep := range eps {
		if public[strings.ToLower(ep)] {
			return true
		}
	}
	return false
}

// hasMiddlewareOfType checks whether the router's middleware list contains
// at least one middleware whose type is in the target set.
// Router middleware references may or may not carry the @provider suffix.
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
	// Strip provider suffix from the ref and compare against base names.
	base := strings.SplitN(ref, "@", 2)[0]
	for key, mw := range all {
		if strings.SplitN(key, "@", 2)[0] == base {
			return mw, true
		}
	}
	return traefik.Middleware{}, false
}
