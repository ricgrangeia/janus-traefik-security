package traefik

import (
	"strings"

	"github.com/janus-project/janus/domain"
)

// secureEntrypoints are entrypoint names that imply TLS is expected.
var secureEntrypoints = map[string]bool{
	"websecure": true,
	"https":     true,
	"443":       true,
}

// ToSnapshot translates a Traefik RawData API response into a domain NetworkSnapshot.
// All Traefik-specific naming conventions (raw middleware types, entrypoint names)
// are resolved here so the domain layer stays infrastructure-agnostic.
func ToSnapshot(raw *RawData, pulseAlerts []domain.PulseAlert, traefikOK bool) domain.NetworkSnapshot {
	return domain.NetworkSnapshot{
		TraefikOK:   traefikOK,
		Routers:     mapRouters(raw),
		Middlewares: mapMiddlewares(raw.Middlewares),
		PulseAlerts: pulseAlerts,
	}
}

func mapRouters(raw *RawData) []domain.Router {
	routers := make([]domain.Router, 0, len(raw.Routers))
	for name, r := range raw.Routers {
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
			IsRedirect:  isRedirectRouter(r, raw.Middlewares),
			Status:      r.Status,
		})
	}
	return routers
}

func mapMiddlewares(raw map[string]Middleware) map[string]domain.MiddlewareDescriptor {
	out := make(map[string]domain.MiddlewareDescriptor, len(raw))
	for name, m := range raw {
		out[name] = domain.MiddlewareDescriptor{
			Name:     name,
			Type:     resolveMiddlewareType(m.Type),
			Provider: m.Provider,
		}
	}
	return out
}

// resolveMiddlewareType maps Traefik's raw type string to a domain MiddlewareType.
func resolveMiddlewareType(rawType string) domain.MiddlewareType {
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

func hasSecureEntrypoint(eps []string) bool {
	for _, ep := range eps {
		if secureEntrypoints[strings.ToLower(ep)] {
			return true
		}
	}
	return false
}

// isRedirectRouter returns true when every middleware on the router is a
// redirectscheme — the router's sole purpose is HTTP→HTTPS redirection.
func isRedirectRouter(r Router, middlewares map[string]Middleware) bool {
	if len(r.Middlewares) == 0 {
		return false
	}
	for _, ref := range r.Middlewares {
		mw, ok := resolveRawMiddleware(ref, middlewares)
		if !ok || strings.ToLower(mw.Type) != "redirectscheme" {
			return false
		}
	}
	return true
}

func resolveRawMiddleware(ref string, all map[string]Middleware) (Middleware, bool) {
	if mw, ok := all[ref]; ok {
		return mw, true
	}
	base := strings.SplitN(ref, "@", 2)[0]
	for key, mw := range all {
		if strings.SplitN(key, "@", 2)[0] == base {
			return mw, true
		}
	}
	return Middleware{}, false
}
