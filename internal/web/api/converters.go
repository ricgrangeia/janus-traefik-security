package api

import (
	"github.com/janus-project/janus/domain"
	"github.com/janus-project/janus/internal/app"
	traefikinfra "github.com/janus-project/janus/internal/infrastructure/traefik"
)

func ToRouterAuditDTOs(audits []domain.RouterAudit) []RouterAuditDTO {
	out := make([]RouterAuditDTO, 0, len(audits))
	for _, a := range audits {
		dto := RouterAuditDTO{
			RouterName:  a.Router.Name,
			Rule:        a.Router.Rule,
			Provider:    a.Router.Provider,
			Score:       a.Score,
			IsRedirect:  a.Router.IsRedirect,
			AIReasoning: a.AIReasoning,
			Issues:      make([]IssueDTO, 0, len(a.Issues)),
		}
		if !a.IsClean() && !a.Router.IsRedirect {
			dto.RemediationSnippet = app.FormatDockerLabels(a.Router.Name, a.Issues, nil)
		}
		for _, pv := range a.PolicyViolations {
			missing := make([]string, len(pv.Missing))
			for i, m := range pv.Missing {
				missing[i] = string(m)
			}
			dto.PolicyViolations = append(dto.PolicyViolations, PolicyViolationDTO{
				PolicyName: pv.PolicyName,
				Pattern:    pv.Pattern,
				Missing:    missing,
			})
		}
		for _, issue := range a.Issues {
			dto.Issues = append(dto.Issues, IssueDTO{
				Code:        issue.Code,
				Description: issue.Description,
				Severity:    issue.Severity.String(),
				AIReasoning: issue.AIReasoning,
			})
		}
		out = append(out, dto)
	}
	return out
}

func ToPulseAlertDTOs(alerts []domain.PulseAlert) []PulseAlertDTO {
	out := make([]PulseAlertDTO, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, PulseAlertDTO{
			ServiceName: a.ServiceName,
			Total:       a.Total,
			Count4xx:    a.Count4xx,
			Count5xx:    a.Count5xx,
			ErrorRate:   a.ErrorRate,
		})
	}
	return out
}

func ToOverviewDTO(ov *traefikinfra.OverviewDTO) *OverviewDTO {
	return &OverviewDTO{
		HTTP: HTTPStatsDTO{
			Routers:     EntityStatsDTO{Total: ov.HTTP.Routers.Total, Warnings: ov.HTTP.Routers.Warnings, Errors: ov.HTTP.Routers.Errors},
			Services:    EntityStatsDTO{Total: ov.HTTP.Services.Total, Warnings: ov.HTTP.Services.Warnings, Errors: ov.HTTP.Services.Errors},
			Middlewares: EntityStatsDTO{Total: ov.HTTP.Middlewares.Total, Warnings: ov.HTTP.Middlewares.Warnings, Errors: ov.HTTP.Middlewares.Errors},
		},
		Providers: ov.Providers,
	}
}

func ToAIInsightsDTO(ai *domain.AIInsights) *AIInsightsDTO {
	dto := &AIInsightsDTO{
		Thought:          ai.Thought,
		Summary:          ai.Summary,
		Severity:         ai.Severity,
		Correlations:     ai.Correlations,
		PromptTokens:     ai.PromptTokens,
		CompletionTokens: ai.CompletionTokens,
		TokensUsed:       ai.TokensUsed,
		LatencyMs:        ai.LatencyMs,
		GeneratedAt:      ai.GeneratedAt,
		Fallback:         ai.Fallback,
	}
	if len(ai.RouterInsights) > 0 {
		dto.RouterInsights = make(map[string]RouterInsightDTO, len(ai.RouterInsights))
		for name, ri := range ai.RouterInsights {
			dto.RouterInsights[name] = RouterInsightDTO{
				Analysis:      ri.Analysis,
				AttackSurface: ri.AttackSurface,
				Severity:      ri.Severity,
				Remediation:   ri.Remediation,
			}
		}
	}
	for _, s := range ai.ShadowAPIs {
		dto.ShadowAPIs = append(dto.ShadowAPIs, ShadowAPIDTO{RouterName: s.RouterName, Reason: s.Reason})
	}
	for _, a := range ai.AggressivityAlerts {
		dto.AggressivityAlerts = append(dto.AggressivityAlerts, AggressivityDTO{
			ServiceName: a.ServiceName,
			Assessment:  a.Assessment,
			Reasoning:   a.Reasoning,
			SuspectedIP: a.SuspectedIP,
		})
	}
	return dto
}

func ToDriftAlertDTOs(alerts []domain.DriftAlert) []DriftAlertDTO {
	out := make([]DriftAlertDTO, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, DriftAlertDTO{
			RouterName: a.RouterName,
			LostChecks: a.LostChecks,
			OldScore:   a.OldScore,
			NewScore:   a.NewScore,
		})
	}
	return out
}

func ToPolicyDTOs(policies []domain.Policy) []PolicyDTO {
	out := make([]PolicyDTO, 0, len(policies))
	for _, p := range policies {
		req := make([]string, len(p.Required))
		for i, r := range p.Required {
			req[i] = string(r)
		}
		out = append(out, PolicyDTO{
			Name:        p.Name,
			Pattern:     p.Pattern,
			Required:    req,
			Description: p.Description,
		})
	}
	return out
}
