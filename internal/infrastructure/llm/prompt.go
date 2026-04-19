package llm

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/janus-project/janus/domain"
)

// SystemPrompt instructs Janus-AI on its role, chain-of-thought style, and JSON output schema.
const SystemPrompt = `You are Janus-AI, an expert Cloud Security Researcher and DevSecOps Lead specialising in Traefik reverse proxy hardening and architectural security audits.

Your mission is to detect "Architectural Drift" — inconsistencies in security posture across services that indicate systemic policy failures, not just isolated misconfigurations.

Your output MUST be valid JSON and nothing else — no markdown, no prose before or after the JSON.

Use this exact schema:
{
  "thought": "<chain-of-thought block: reason through the network before scoring — which services are similar? which gaps are shared? what is the worst-case attack path?>",
  "summary": "<2-3 sentence overall security assessment>",
  "severity": <0-10 overall severity where 0=fully secure, 10=critical exposure>,
  "correlations": [
    "<systemic pattern observed across multiple routers, e.g. all internal tools share the same auth gap>"
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
      "reasoning": "<concise classification explanation>"
    }
  ],
  "router_insights": {
    "<router_name@provider>": {
      "analysis": "<detailed security assessment for this specific router>",
      "attack_surface": "<how an external attacker would likely try to exploit this configuration>",
      "severity": <0-10 severity for this router>,
      "remediation": ["<specific Traefik label or config the developer should add>"]
    }
  }
}

Focus areas:
1. THOUGHT — before scoring, reason: which services are similar categories? which share the same gap? what is the worst realistic attack path given the rules and entrypoints?
2. CORRELATION — identify routers sharing the same security gap pattern (systemic policy failure vs isolated misconfiguration).
3. SHADOW APIS — flag routers whose rule or name implies internal tools, admin panels, debug endpoints, metrics, or undocumented APIs exposed without authentication.
4. AGGRESSIVITY — for services with elevated 4xx/5xx error rates, classify whether the pattern looks like automated bot scanning, application bugs, or legitimate traffic spikes.
5. ATTACK SURFACE — for each flagged router, describe specifically how an attacker would try to exploit the configuration based on its Host/Path rules.`

// aiResponseDTO mirrors the JSON the model is instructed to return.
type aiResponseDTO struct {
	Thought              string                        `json:"thought"`
	Summary              string                        `json:"summary"`
	Severity             int                           `json:"severity"`
	Correlations         []string                      `json:"correlations"`
	ShadowAPIs           []shadowAPIDTO                `json:"shadow_apis"`
	AggressivityAnalysis []aggressivityDTO             `json:"aggressivity_analysis"`
	RouterInsights       map[string]routerInsightDTO   `json:"router_insights"`
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

type routerInsightDTO struct {
	Analysis      string   `json:"analysis"`
	AttackSurface string   `json:"attack_surface"`
	Severity      int      `json:"severity"`
	Remediation   []string `json:"remediation"`
}

// BuildContext serialises the AuditReport and NetworkSnapshot into the user message
// sent to the model. The full JSON state is included without truncation — Qwen 2.5
// supports a 100k-token context window. env and knownMiddlewares add deployment
// metadata so the model can reason about what is intentionally secure vs misconfigured.
func BuildContext(
	report domain.AuditReport,
	snapshot domain.NetworkSnapshot,
	env string,
	knownMiddlewares []string,
) string {
	reportJSON, _ := json.MarshalIndent(report, "", "  ")
	snapshotJSON, _ := json.MarshalIndent(snapshot, "", "  ")

	middlewareList := "none configured"
	if len(knownMiddlewares) > 0 {
		middlewareList = strings.Join(knownMiddlewares, ", ")
	}

	return fmt.Sprintf(`=== JANUS NETWORK SNAPSHOT ===
Environment          : %s
Known Secure Middlewares: %s
Overall Score        : %d / 100
Traefik Reachable    : %v
Snapshot Timestamp   : %s

--- Security Audit Results (JSON) ---
%s

--- Full Traefik Network State (JSON) ---
%s
`,
		env,
		middlewareList,
		report.OverallScore,
		report.TraefikOK,
		report.GeneratedAt.Format("2006-01-02T15:04:05Z"),
		string(reportJSON),
		string(snapshotJSON),
	)
}

// ParseResponse converts the model's raw JSON reply into the internal DTO.
func ParseResponse(raw string) (*aiResponseDTO, error) {
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
