package app

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/janus-project/janus/domain"
)

// ── Policy loading ────────────────────────────────────────────────────────

// policyDTO is the JSON representation of a single policy.
type policyDTO struct {
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	Required    []string `json:"required"`
	Description string   `json:"description"`
}

type policiesFile struct {
	Policies []policyDTO `json:"policies"`
}

// LoadPolicies reads policy definitions from a JSON file.
// Returns nil (no policies, no error) if path is empty or the file doesn't exist.
func LoadPolicies(path string) ([]domain.Policy, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Warn("policies file not found — running without user-defined policies", "path", path)
			return nil, nil
		}
		return nil, fmt.Errorf("load policies %s: %w", path, err)
	}

	var pf policiesFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policies %s: %w", path, err)
	}

	policies := make([]domain.Policy, 0, len(pf.Policies))
	for _, dto := range pf.Policies {
		p := domain.Policy{
			Name:        dto.Name,
			Pattern:     dto.Pattern,
			Description: dto.Description,
		}
		for _, r := range dto.Required {
			p.Required = append(p.Required, domain.MiddlewareRequirement(r))
		}
		policies = append(policies, p)
	}

	slog.Info("policies loaded", "count", len(policies), "path", path)
	return policies, nil
}

// ── Policy enforcement ────────────────────────────────────────────────────

// CheckPolicies enriches an AuditReport by applying user-defined policies to each router.
// Violations are recorded per-router in RouterAudit.PolicyViolations.
func CheckPolicies(
	report domain.AuditReport,
	snapshot domain.NetworkSnapshot,
	policies []domain.Policy,
) domain.AuditReport {
	if len(policies) == 0 {
		return report
	}

	enriched := make([]domain.RouterAudit, len(report.RouterAudits))
	for i, ra := range report.RouterAudits {
		if ra.Router.IsRedirect {
			enriched[i] = ra
			continue
		}
		for _, policy := range policies {
			if !matchesPattern(policy.Pattern, ra.Router.Name) {
				continue
			}
			var missing []domain.MiddlewareRequirement
			for _, req := range policy.Required {
				mwType := req.ToMiddlewareType()
				if mwType != domain.MiddlewareUnknown && !snapshot.HasMiddlewareType(ra.Router, mwType) {
					missing = append(missing, req)
				}
			}
			if len(missing) > 0 {
				ra.PolicyViolations = append(ra.PolicyViolations, domain.PolicyViolation{
					PolicyName: policy.Name,
					Pattern:    policy.Pattern,
					Missing:    missing,
				})
			}
		}
		enriched[i] = ra
	}
	report.RouterAudits = enriched
	return report
}

// matchesPattern checks whether a router name matches a glob-style policy pattern.
// Supported forms: *suffix, prefix*, *contains*, exact.
// Matching is case-insensitive and operates on the base name (before @provider).
func matchesPattern(pattern, name string) bool {
	base := name
	if idx := strings.Index(name, "@"); idx > 0 {
		base = name[:idx]
	}
	base = strings.ToLower(base)
	p := strings.ToLower(pattern)

	switch {
	case p == "*":
		return true
	case strings.HasPrefix(p, "*") && strings.HasSuffix(p, "*") && len(p) > 1:
		return strings.Contains(base, p[1:len(p)-1])
	case strings.HasPrefix(p, "*"):
		return strings.HasSuffix(base, p[1:])
	case strings.HasSuffix(p, "*"):
		return strings.HasPrefix(base, p[:len(p)-1])
	default:
		return base == p || name == pattern
	}
}
