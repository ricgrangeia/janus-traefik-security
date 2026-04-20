package domain

// MiddlewareRequirement is the policy-layer name for a required middleware type.
type MiddlewareRequirement string

const (
	RequireAuth        MiddlewareRequirement = "auth"
	RequireRateLimit   MiddlewareRequirement = "ratelimit"
	RequireIPAllowlist MiddlewareRequirement = "ipallowlist"
	RequireWAF         MiddlewareRequirement = "waf"
)

// ToMiddlewareType maps the policy requirement to the domain MiddlewareType.
func (r MiddlewareRequirement) ToMiddlewareType() MiddlewareType {
	switch r {
	case RequireAuth:
		return MiddlewareAuth
	case RequireRateLimit:
		return MiddlewareRateLimit
	case RequireIPAllowlist:
		return MiddlewareIPAllowlist
	case RequireWAF:
		return MiddlewareWAF
	default:
		return MiddlewareUnknown
	}
}

// Policy defines security requirements for routers whose names match a pattern.
type Policy struct {
	Name        string
	Pattern     string                 // glob-style: *suffix, prefix*, *contains*, exact
	Required    []MiddlewareRequirement
	Description string
}

// PolicyViolation records that a router failed to satisfy a policy.
type PolicyViolation struct {
	PolicyName string
	Pattern    string
	Missing    []MiddlewareRequirement
}

// DriftAlert is raised when a router's security posture regresses between two audits.
type DriftAlert struct {
	RouterName string
	LostChecks []string // human-readable description of each regressed check
	OldScore   int
	NewScore   int
}
