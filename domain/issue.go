package domain

// Severity represents the impact level of a security issue on a router's score.
type Severity int

const (
	SeverityLow      Severity = 1 // informational — fix when convenient
	SeverityMedium   Severity = 2 // should fix
	SeverityHigh     Severity = 3 // fix soon
	SeverityCritical Severity = 4 // fix immediately
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ScoreDeduction returns how many points to subtract from a router's score (0–100).
func (s Severity) ScoreDeduction() int {
	switch s {
	case SeverityCritical:
		return 40
	case SeverityHigh:
		return 30
	case SeverityMedium:
		return 20
	case SeverityLow:
		return 10
	default:
		return 0
	}
}

// SecurityIssue is an entity representing a detected vulnerability on a router.
// Predefined issues are declared as package-level values so auditor
// implementations can reference them without re-defining descriptions.
// AIReasoning is populated asynchronously by the AI analyst background worker;
// it is empty until the first AI audit completes.
type SecurityIssue struct {
	Code        string
	Description string
	Severity    Severity
	AIReasoning string // contextual explanation from the AI analyst; empty if AI is offline
}

// Well-known security issues detected by the Auditor.
var (
	IssueNoAuth = SecurityIssue{
		Code:        "SEC-001",
		Description: "No authentication middleware (basicAuth / forwardAuth / digestAuth)",
		Severity:    SeverityCritical,
	}
	IssueNoTLS = SecurityIssue{
		Code:        "SEC-002",
		Description: "No TLS configured on secure entrypoint (websecure)",
		Severity:    SeverityHigh,
	}
	IssueNoRateLimit = SecurityIssue{
		Code:        "SEC-003",
		Description: "No rate limiting middleware",
		Severity:    SeverityMedium,
	}
	IssueNoIPAllowlist = SecurityIssue{
		Code:        "SEC-004",
		Description: "No IP allowlist middleware",
		Severity:    SeverityLow,
	}
)
