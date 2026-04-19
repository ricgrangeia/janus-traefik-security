package traefik

import (
	"strings"

	"github.com/janus-project/janus/domain"
)

// secureEntrypoints are Traefik entrypoint names that imply TLS is expected.
// This knowledge lives in the ACL — not in the domain — because "websecure"
// is a Traefik convention, not a universal concept.
var secureEntrypoints = map[string]bool{
	"websecure": true,
	"https":     true,
	"443":       true,
}

// ToSnapshot is the Anti-Corruption Layer entry point.
// It translates Traefik's API DTOs into a domain.NetworkSnapshot,
// resolving all Traefik-specific naming conventions (raw middleware types,
// entrypoint names, provider suffixes) so the domain stays infrastructure-agnostic.
func ToSnapshot(raw *RawDataDTO, pulseAlerts []domain.PulseAlert, traefikOK bool) domain.NetworkSnapshot {
	return domain.NetworkSnapshot{
		TraefikOK:   traefikOK,
		Routers:     mapRouters(raw),
		Middlewares: mapMiddlewares(raw.Middlewares),
		PulseAlerts: pulseAlerts,
	}
}

// ── Private mapping functions ─────────────────────────────────────────────

func mapRouters(raw *RawDataDTO) []domain.Router {
	routers := make([]domain.Router, 0, len(raw.Routers))
	for name, r := range raw.Routers {
		// Traefik's own internal routers are infrastructure noise — skip them.
		if strings.HasSuffix(name, "@internal") {
			continue
		}
		routers = append(routers, domain.Router{
			Name:        name,
			Rule:        r.Rule,
			Provider:    r.Provider,
			Entrypoints: r.EntryPoints,
			Middlewares: r.Middlewares,
			HasTLS:      r.TLS != nil,
			IsHTTPS:     hasSecureEntrypoint(r.EntryPoints),
			IsRedirect:  isRedirectOnlyRouter(r, raw.Middlewares),
			Status:      r.Status,
		})
	}
	return routers
}

func mapMiddlewares(raw map[string]MiddlewareDTO) map[string]domain.MiddlewareDescriptor {
	out := make(map[string]domain.MiddlewareDescriptor, len(raw))
	for name, m := range raw {
		out[name] = domain.MiddlewareDescriptor{
			Name:     name,
			Type:     mapMiddlewareType(m.Type),
			Provider: m.Provider,
		}
	}
	return out
}

// mapMiddlewareType resolves Traefik's raw type string to a domain MiddlewareType.
// This is the single place where Traefik type names are known to the codebase.
func mapMiddlewareType(rawType string) domain.MiddlewareType {
	switch strings.ToLower(rawType) {
	case "basicauth", "digestauth", "forwardauth":
		return domain.MiddlewareAuth
	case "ratelimit":
		return domain.MiddlewareRateLimit
	case "ipallowlist", "ipwhitelist":
		return domain.MiddlewareIPAllowlist
	default:
		return domain.MiddlewareUnknown
	}
}

// isRedirectOnlyRouter returns true when every middleware on the router is a
// redirectscheme — meaning its sole purpose is HTTP→HTTPS redirection.
func isRedirectOnlyRouter(r RouterDTO, middlewares map[string]MiddlewareDTO) bool {
	if len(r.Middlewares) == 0 {
		return false
	}
	for _, ref := range r.Middlewares {
		mw, ok := resolveDTO(ref, middlewares)
		if !ok || strings.ToLower(mw.Type) != "redirectscheme" {
			return false
		}
	}
	return true
}

func hasSecureEntrypoint(eps []string) bool {
	for _, ep := range eps {
		if secureEntrypoints[strings.ToLower(ep)] {
			return true
		}
	}
	return false
}

// resolveDTO looks up a MiddlewareDTO by reference name, handling the optional
// @provider suffix that Traefik may or may not include in router middleware lists.
func resolveDTO(ref string, all map[string]MiddlewareDTO) (MiddlewareDTO, bool) {
	if mw, ok := all[ref]; ok {
		return mw, true
	}
	base := strings.SplitN(ref, "@", 2)[0]
	for key, mw := range all {
		if strings.SplitN(key, "@", 2)[0] == base {
			return mw, true
		}
	}
	return MiddlewareDTO{}, false
}
