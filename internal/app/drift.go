package app

import (
	"fmt"

	"github.com/janus-project/janus/domain"
)

// DetectDrift compares prev and curr AuditReports.
// A drift is recorded when a router previously passed a security check but
// now fails it (i.e., a middleware was removed or a rule was changed).
// Returns nil when no regression is detected or when prev has no data.
func DetectDrift(prev, curr domain.AuditReport) []domain.DriftAlert {
	if prev.GeneratedAt.IsZero() || len(prev.RouterAudits) == 0 {
		return nil
	}

	// Index previous audits by router name for O(1) lookup.
	prevMap := make(map[string]domain.RouterAudit, len(prev.RouterAudits))
	for _, ra := range prev.RouterAudits {
		prevMap[ra.Router.Name] = ra
	}

	var alerts []domain.DriftAlert
	for _, cur := range curr.RouterAudits {
		if cur.Router.IsRedirect {
			continue
		}
		old, exists := prevMap[cur.Router.Name]
		if !exists || cur.Score >= old.Score {
			continue // new router or no regression
		}

		// Identify checks that were previously passing but now failing.
		oldFailed := make(map[string]bool, len(old.Issues))
		for _, issue := range old.Issues {
			oldFailed[issue.Code] = true
		}

		var lost []string
		for _, issue := range cur.Issues {
			if !oldFailed[issue.Code] {
				lost = append(lost, fmt.Sprintf("%s: %s", issue.Code, issue.Description))
			}
		}

		if len(lost) > 0 {
			alerts = append(alerts, domain.DriftAlert{
				RouterName: cur.Router.Name,
				LostChecks: lost,
				OldScore:   old.Score,
				NewScore:   cur.Score,
			})
		}
	}
	return alerts
}
