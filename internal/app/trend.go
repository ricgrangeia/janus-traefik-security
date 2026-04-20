package app

import (
	"github.com/janus-project/janus/domain"
	"github.com/janus-project/janus/internal/infrastructure/storage"
)

// CheckSecurityDecline returns true when the most recently stored score is
// lower than the average of the previous `lookback` scores — indicating that
// the security posture has declined since the last audits.
// Returns false when there is not enough history to make a determination.
func CheckSecurityDecline(store storage.RichStore, lookback int) bool {
	scores := store.GetLatestScores(lookback + 1)
	if len(scores) < lookback+1 {
		return false
	}
	// scores[0] is the most recent (just saved); compare against avg of the rest.
	current := scores[0]
	sum := 0
	for _, s := range scores[1:] {
		sum += s
	}
	avg := sum / lookback
	return current < avg
}

// ToRouterResults converts domain RouterAudits into storage RouterResult records
// ready to be persisted alongside an audit.
func ToRouterResults(report domain.AuditReport) []storage.RouterResult {
	out := make([]storage.RouterResult, 0, len(report.RouterAudits))
	for _, ra := range report.RouterAudits {
		if ra.Router.IsRedirect {
			continue
		}
		codes := make([]string, 0, len(ra.Issues))
		for _, issue := range ra.Issues {
			codes = append(codes, issue.Code)
		}
		severity := 0
		if report.AIInsights != nil {
			if ri, ok := report.AIInsights.RouterInsights[ra.Router.Name]; ok {
				severity = ri.Severity
			}
		}
		out = append(out, storage.RouterResult{
			RouterName:         ra.Router.Name,
			Score:              ra.Score,
			Severity:           severity,
			AIReasoning:        ra.AIReasoning,
			RemediationSnippet: FormatDockerLabels(ra.Router.Name, ra.Issues, nil),
			IssueCodes:         storage.IssueCodesCSV(codes),
		})
	}
	return out
}
