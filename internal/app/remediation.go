package app

import (
	"fmt"
	"strings"

	"github.com/janus-project/janus/domain"
)

// FormatDockerLabels returns a copy-pasteable Docker Compose labels block.
// If AI remediation strings are provided they are used directly;
// otherwise standard labels are generated from the heuristic issues.
func FormatDockerLabels(routerName string, issues []domain.SecurityIssue, aiRemediation []string) string {
	var lines []string
	if len(aiRemediation) > 0 {
		lines = aiRemediation
	} else {
		lines = standardLabels(routerName, issues)
	}
	if len(lines) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("labels:\n")
	for _, l := range lines {
		l = strings.Trim(l, `"'`) // normalise — AI sometimes wraps in quotes
		fmt.Fprintf(&sb, "  - \"%s\"\n", l)
	}
	return sb.String()
}

// standardLabels generates Traefik label suggestions from heuristic SecurityIssues
// when the AI analyst is not available or did not produce remediation for this router.
func standardLabels(routerName string, issues []domain.SecurityIssue) []string {
	base := routerName
	if idx := strings.Index(routerName, "@"); idx > 0 {
		base = routerName[:idx]
	}

	var mwNames []string
	var extraLabels []string

	for _, issue := range issues {
		switch issue.Code {
		case "SEC-001": // missing auth
			name := base + "-auth"
			mwNames = append(mwNames, name+"@docker")
			extraLabels = append(extraLabels,
				fmt.Sprintf("traefik.http.middlewares.%s.basicauth.users=admin:$$apr1$$replace-me$$hash", name),
			)
		case "SEC-003": // missing rate limit
			name := base + "-ratelimit"
			mwNames = append(mwNames, name+"@docker")
			extraLabels = append(extraLabels,
				fmt.Sprintf("traefik.http.middlewares.%s.ratelimit.average=100", name),
				fmt.Sprintf("traefik.http.middlewares.%s.ratelimit.burst=50", name),
			)
		case "SEC-004": // missing IP allowlist
			name := base + "-allowlist"
			mwNames = append(mwNames, name+"@docker")
			extraLabels = append(extraLabels,
				fmt.Sprintf("traefik.http.middlewares.%s.ipallowlist.sourcerange=10.0.0.0/8,192.168.0.0/16", name),
			)
		}
	}

	if len(mwNames) == 0 {
		return nil
	}

	header := fmt.Sprintf("traefik.http.routers.%s.middlewares=%s", base, strings.Join(mwNames, ","))
	return append([]string{header}, extraLabels...)
}
