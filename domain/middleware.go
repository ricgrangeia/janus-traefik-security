package domain

// MiddlewareType is a value object identifying the security category of a middleware.
// The infrastructure mapper is responsible for translating Traefik's raw type
// strings (e.g. "basicauth") into these domain-level constants.
type MiddlewareType string

const (
	MiddlewareAuth        MiddlewareType = "auth"         // basicauth, digestauth, forwardauth
	MiddlewareRateLimit   MiddlewareType = "rate_limit"   // ratelimit
	MiddlewareIPAllowlist MiddlewareType = "ip_allowlist" // ipallowlist, ipwhitelist
	MiddlewareWAF         MiddlewareType = "waf"          // future: plugin-based WAF
	MiddlewareUnknown     MiddlewareType = ""
)

// MiddlewareDescriptor is a value object describing a resolved middleware instance.
// Equality is determined by field values, not by object identity.
type MiddlewareDescriptor struct {
	Name     string
	Type     MiddlewareType
	Provider string
}
