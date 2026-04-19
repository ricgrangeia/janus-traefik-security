package llm

import (
	"fmt"
	"time"

	"github.com/janus-project/janus/domain"
)

// VLLMAnalyst implements domain.AIAnalyst using a local vLLM server.
type VLLMAnalyst struct {
	client *Client
}

// NewAnalyst creates a VLLMAnalyst backed by the given Client.
func NewAnalyst(client *Client) domain.AIAnalyst {
	return &VLLMAnalyst{client: client}
}

// Analyze sends the full audit context to the vLLM model, parses the structured
// JSON response, and returns an enriched AuditReport.
// If the model is unreachable or returns unparseable output, the original report
// is returned unchanged so Janus continues to serve basic gap data.
func (a *VLLMAnalyst) Analyze(report domain.AuditReport, snapshot domain.NetworkSnapshot) (domain.AuditReport, error) {
	start := time.Now()

	userContent := BuildContext(report, snapshot)
	reply, usage, err := a.client.Chat(SystemPrompt, userContent)
	if err != nil {
		return report, fmt.Errorf("vLLM chat: %w", err)
	}

	dto, err := ParseResponse(reply)
	if err != nil {
		return report, fmt.Errorf("parse AI response: %w", err)
	}

	insights := &domain.AIInsights{
		Summary:         dto.Summary,
		Correlations:    dto.Correlations,
		RouterReasoning: dto.RouterInsights,
		TokensUsed:      usage.TotalTokens,
		LatencyMs:       time.Since(start).Milliseconds(),
		GeneratedAt:     time.Now().UTC(),
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

	// Overlay per-router AI reasoning onto the RouterAudit entries.
	enriched := make([]domain.RouterAudit, len(report.RouterAudits))
	for i, ra := range report.RouterAudits {
		if reasoning, ok := insights.RouterReasoning[ra.Router.Name]; ok {
			ra.AIReasoning = reasoning
		}
		enriched[i] = ra
	}

	report.RouterAudits = enriched
	report.AIInsights = insights
	return report, nil
}
