package llm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/janus-project/janus/internal/infrastructure/storage"
)

// ConsultPrompt instructs Janus-AI to produce a strategic executive summary from history.
const ConsultPrompt = `You are Janus-AI, a senior DevSecOps architect reviewing historical security audit data.

Analyze the provided audit history and write a concise executive report as exactly 3 paragraphs of plain text. No markdown, no bullet points, no headers — just 3 clean paragraphs separated by blank lines.

Paragraph 1 — TREND: Is the overall security posture improving, declining, or stagnant? Reference the score range and severity changes observed over the period.

Paragraph 2 — OFFENDERS: Which service pattern or router type appears most frequently in red flags, shadow API detections, or high-severity events? Be specific about naming patterns.

Paragraph 3 — RECOMMENDATIONS: Provide 2-3 concrete, actionable steps the team should take next based on the history, ordered by impact.`

// BuildConsultContext formats audit history into the user message for the consult prompt.
func BuildConsultContext(history []storage.AuditSummary) string {
	if len(history) == 0 {
		return "No audit history available."
	}

	// Summary statistics
	var minScore, maxScore, totalScore int
	minScore = 100
	var highSeverityCount, shadowAPITotal, fallbackCount int
	for _, h := range history {
		totalScore += h.OverallScore
		if h.OverallScore < minScore {
			minScore = h.OverallScore
		}
		if h.OverallScore > maxScore {
			maxScore = h.OverallScore
		}
		if h.Severity >= 7 {
			highSeverityCount++
		}
		shadowAPITotal += h.ShadowAPIs
		if h.Fallback {
			fallbackCount++
		}
	}
	avgScore := totalScore / len(history)

	// Score trend: last 10 entries
	recent := history
	if len(recent) > 10 {
		recent = recent[len(recent)-10:]
	}
	var trendParts []string
	for _, h := range recent {
		trendParts = append(trendParts, fmt.Sprintf("%s→%d(sev:%d,flags:%d,shadow:%d)",
			h.Timestamp.Format(time.RFC3339)[:10],
			h.OverallScore,
			h.Severity,
			h.RedFlags,
			h.ShadowAPIs,
		))
	}

	full, _ := json.MarshalIndent(history, "", "  ")

	return fmt.Sprintf(`=== AUDIT HISTORY SUMMARY ===
Period       : %s to %s
Total Audits : %d
Score Range  : %d – %d (avg: %d)
High Severity Events (7+): %d
Shadow APIs Detected: %d
AI Fallback Runs: %d

Recent Score Trend (newest last):
%s

Full History (JSON):
%s`,
		history[0].Timestamp.Format("2006-01-02"),
		history[len(history)-1].Timestamp.Format("2006-01-02"),
		len(history),
		minScore, maxScore, avgScore,
		highSeverityCount,
		shadowAPITotal,
		fallbackCount,
		strings.Join(trendParts, "\n"),
		string(full),
	)
}
