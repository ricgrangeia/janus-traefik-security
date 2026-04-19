package llm

import (
	"fmt"
	"time"

	"github.com/janus-project/janus/domain"
)

// VLLMAnalyst implements domain.AIAnalyst using a local vLLM server.
type VLLMAnalyst struct {
	client           *Client
	env              string
	knownMiddlewares []string
}

// NewAnalyst creates a VLLMAnalyst backed by the given Client.
// env is the deployment label (e.g. "production") and knownMiddlewares is the
// list of middleware names considered trusted/secure in this environment.
func NewAnalyst(client *Client, env string, knownMiddlewares []string) domain.AIAnalyst {
	if env == "" {
		env = "production"
	}
	return &VLLMAnalyst{
		client:           client,
		env:              env,
		knownMiddlewares: knownMiddlewares,
	}
}

// Analyze sends the full audit context to the vLLM model, parses the structured
// JSON response, and returns an enriched AuditReport.
// If the model is unreachable or returns unparseable output the original report
// is returned with a Fallback AIInsights so the UI can show "AI Unavailable".
func (a *VLLMAnalyst) Analyze(report domain.AuditReport, snapshot domain.NetworkSnapshot) (domain.AuditReport, error) {
	start := time.Now()

	userContent := BuildContext(report, snapshot, a.env, a.knownMiddlewares)
	reply, usage, err := a.client.Chat(SystemPrompt, userContent)
	if err != nil {
		report.AIInsights = fallbackInsights(err)
		return report, fmt.Errorf("vLLM chat: %w", err)
	}

	dto, err := ParseResponse(reply)
	if err != nil {
		report.AIInsights = fallbackInsights(err)
		return report, fmt.Errorf("parse AI response: %w", err)
	}

	insights := &domain.AIInsights{
		Thought:          dto.Thought,
		Summary:          dto.Summary,
		Severity:         dto.Severity,
		Correlations:     dto.Correlations,
		RouterInsights:   make(map[string]domain.RouterInsight, len(dto.RouterInsights)),
		PromptTokens:     usage.PromptTokens,
		CompletionTokens: usage.CompletionTokens,
		TokensUsed:       usage.TotalTokens,
		LatencyMs:        time.Since(start).Milliseconds(),
		GeneratedAt:      time.Now().UTC(),
	}

	for name, ri := range dto.RouterInsights {
		insights.RouterInsights[name] = domain.RouterInsight{
			Analysis:      ri.Analysis,
			AttackSurface: ri.AttackSurface,
			Severity:      ri.Severity,
			Remediation:   ri.Remediation,
		}
	}
	for _, s := range dto.ShadowAPIs {
		insights.ShadowAPIs = append(insights.ShadowAPIs, domain.ShadowAPIAlert{
			RouterName: s.RouterName,
			Reason:     s.Reason,
		})
	}
	for _, ag := range dto.AggressivityAnalysis {
		insights.AggressivityAlerts = append(insights.AggressivityAlerts, domain.AggressivityAlert{
			ServiceName: ag.ServiceName,
			Assessment:  ag.Assessment,
			Reasoning:   ag.Reasoning,
		})
	}

	// Overlay per-router AI reasoning onto RouterAudit entries.
	enriched := make([]domain.RouterAudit, len(report.RouterAudits))
	for i, ra := range report.RouterAudits {
		if ri, ok := insights.RouterInsights[ra.Router.Name]; ok {
			ra.AIReasoning = ri.Analysis
		}
		enriched[i] = ra
	}

	report.RouterAudits = enriched
	report.AIInsights = insights
	return report, nil
}

func fallbackInsights(cause error) *domain.AIInsights {
	return &domain.AIInsights{
		Summary:     "AI analysis currently unavailable.",
		Correlations: []string{cause.Error()},
		GeneratedAt: time.Now().UTC(),
		Fallback:    true,
	}
}
