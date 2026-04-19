package llm

import (
	"encoding/json"
	"fmt"

	"github.com/janus-project/janus/domain"
)

// SystemPrompt instructs the model on its role, output format, and focus areas.
// Stored as a constant so it can be tweaked without touching business logic.
const SystemPrompt = `You are an expert network security analyst specialising in reverse proxy hardening and API security.
You are analysing the live security posture of a Traefik reverse proxy deployment reported by the Janus security tool.

Your output MUST be valid JSON and nothing else — no markdown, no prose before or after the JSON.

Use this exact schema:
{
  "summary": "<2-3 sentence overall security assessment>",
  "correlations": [
    "<pattern observed across multiple routers, e.g. all internal tools share the same gap>"
  ],
  "shadow_apis": [
    {
      "router_name": "<name@provider>",
      "reason": "<why this looks like an undocumented or internal API exposed without auth>"
    }
  ],
  "aggressivity_analysis": [
    {
      "service_name": "<name@provider>",
      "assessment": "<one of: bot_scan | bad_code | legitimate_traffic | unknown>",
      "reasoning": "<concise explanation of your classification>"
    }
  ],
  "router_insights": {
    "<router_name@provider>": "<specific, actionable recommendation for this router>"
  }
}

Focus on:
1. CORRELATION — identify routers sharing the same security gap pattern (e.g. all lack rate limiting), which suggests a systemic policy failure, not isolated misconfiguration.
2. SHADOW APIS — flag routers whose rule or name implies an internal tool, admin panel, debug endpoint, or undocumented API that is exposed without authentication.
3. AGGRESSIVITY — for services with elevated 4xx/5xx error rates, classify whether the pattern looks like automated bot scanning, application bugs, or legitimate traffic spikes, based on the rate and distribution.`

// aiResponseDTO mirrors the JSON the model is instructed to return.
type aiResponseDTO struct {
	Summary            string               `json:"summary"`
	Correlations       []string             `json:"correlations"`
	ShadowAPIs         []shadowAPIDTO       `json:"shadow_apis"`
	AggressivityAnalysis []aggressivityDTO  `json:"aggressivity_analysis"`
	RouterInsights     map[string]string    `json:"router_insights"`
}

type shadowAPIDTO struct {
	RouterName string `json:"router_name"`
	Reason     string `json:"reason"`
}

type aggressivityDTO struct {
	ServiceName string `json:"service_name"`
	Assessment  string `json:"assessment"`
	Reasoning   string `json:"reasoning"`
}

// BuildContext serialises the AuditReport and NetworkSnapshot into the user
// message sent to the model. The full JSON state is included — no truncation —
// because Qwen 2.5 7B supports a 100k-token context window.
func BuildContext(report domain.AuditReport, snapshot domain.NetworkSnapshot) string {
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	snapshotJSON, _ := json.MarshalIndent(snapshot, "", "  ")

	return fmt.Sprintf(`=== JANUS SECURITY AUDIT REPORT ===
Overall Score : %d / 100
Traefik OK    : %v
Timestamp     : %s

--- Router Audit Results (JSON) ---
%s

--- Full Traefik Network Snapshot (JSON) ---
%s
`,
		report.OverallScore,
		report.TraefikOK,
		report.GeneratedAt.Format("2006-01-02T15:04:05Z"),
		string(reportJSON),
		string(snapshotJSON),
	)
}

// ParseResponse converts the model's raw JSON reply into domain types.
func ParseResponse(raw string) (*aiResponseDTO, error) {
	// Strip any accidental markdown fences the model may have added.
	clean := stripMarkdownFences(raw)

	var dto aiResponseDTO
	if err := json.Unmarshal([]byte(clean), &dto); err != nil {
		return nil, fmt.Errorf("parse AI response JSON: %w", err)
	}
	return &dto, nil
}

func stripMarkdownFences(s string) string {
	s = trimPrefix(s, "```json")
	s = trimPrefix(s, "```")
	s = trimSuffix(s, "```")
	return s
}

func trimPrefix(s, prefix string) string {
	idx := len(prefix)
	if len(s) >= idx && s[:idx] == prefix {
		// skip the fence line including its newline
		nl := indexOf(s[idx:], '\n')
		if nl >= 0 {
			return s[idx+nl+1:]
		}
		return s[idx:]
	}
	return s
}

func trimSuffix(s, suffix string) string {
	n := len(s) - len(suffix)
	if n >= 0 && s[n:] == suffix {
		return s[:n]
	}
	return s
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
