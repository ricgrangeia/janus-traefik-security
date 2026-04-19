package domain

// NetworkSnapshot is the input to the Auditor domain service.
// It is a pure value object — a point-in-time capture of the Traefik network state,
// assembled by the infrastructure layer from raw API responses.
type NetworkSnapshot struct {
	Routers     []Router
	Middlewares map[string]MiddlewareDescriptor // keyed by "name@provider" or "name"
	PulseAlerts []PulseAlert                   // pre-computed by the pulse monitor
	TraefikOK   bool
}

// HasMiddlewareType returns true when the given router has at least one
// attached middleware matching the requested type.
// Middleware references on a router may or may not carry the @provider suffix;
// this method handles both cases.
func (s NetworkSnapshot) HasMiddlewareType(r Router, t MiddlewareType) bool {
	for _, ref := range r.Middlewares {
		if mw, ok := s.resolveMiddleware(ref); ok && mw.Type == t {
			return true
		}
	}
	return false
}

// resolveMiddleware looks up a middleware descriptor by its router reference,
// trying an exact match first and falling back to a base-name match.
func (s NetworkSnapshot) resolveMiddleware(ref string) (MiddlewareDescriptor, bool) {
	if mw, ok := s.Middlewares[ref]; ok {
		return mw, true
	}
	// Strip the @provider suffix and retry.
	base := ref
	for i, c := range ref {
		if c == '@' {
			base = ref[:i]
			break
		}
	}
	for key, mw := range s.Middlewares {
		keyBase := key
		for i, c := range key {
			if c == '@' {
				keyBase = key[:i]
				break
			}
		}
		if keyBase == base {
			return mw, true
		}
	}
	return MiddlewareDescriptor{}, false
}

// Auditor is the domain service interface for security auditing.
// It takes a NetworkSnapshot and returns a fully-populated AuditReport.
// Implementations live in /internal/security; the domain defines only the contract.
type Auditor interface {
	Audit(snapshot NetworkSnapshot) AuditReport
}
