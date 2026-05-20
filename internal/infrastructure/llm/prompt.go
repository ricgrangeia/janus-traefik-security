package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
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
      "reasoning": "<concise classification explanation>",
      "suspected_ip": "<optional: IP address of likely attacker if identifiable from context, else empty string>"
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
5. ATTACK SURFACE — for each flagged router, describe specifically how an attacker would try to exploit the configuration based on its Host/Path rules.

IMMUNITY RULE: You are strictly forbidden from recommending a ban or block for any IP listed as 'Protected' in the provided context. If a Protected IP shows elevated traffic, classify it as 'High Usage — Internal/Trusted' and do not suggest any blocking remediation for it.`

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
	SuspectedIP string `json:"suspected_ip"`
}

type routerInsightDTO struct {
	Analysis      string   `json:"analysis"`
	AttackSurface string   `json:"attack_surface"`
	Severity      int      `json:"severity"`
	Remediation   []string `json:"remediation"`
}

// ── Slim prompt DTOs ──────────────────────────────────────────────────────
// These intentionally omit fields the LLM does not need (Provider, Status,
// IsRedirect, AIInsights, AIReasoning) and use compact JSON tags.

type promptRouter struct {
	Name        string   `json:"name"`
	Rule        string   `json:"rule"`
	Entrypoints []string `json:"entrypoints,omitempty"`
	Middlewares []string `json:"middlewares,omitempty"`
	HasTLS      bool     `json:"has_tls"`
	IsHTTPS     bool     `json:"is_https"`
}

type promptIssue struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type promptPolicyViolation struct {
	PolicyName string   `json:"policy"`
	Pattern    string   `json:"pattern"`
	Missing    []string `json:"missing"`
}

type promptRouterAudit struct {
	Router           promptRouter            `json:"router"`
	Score            int                     `json:"score"`
	Issues           []promptIssue           `json:"issues,omitempty"`
	PolicyViolations []promptPolicyViolation `json:"policy_violations,omitempty"`
}

type promptPulseAlert struct {
	ServiceName string  `json:"service"`
	ErrorRate   float64 `json:"err_rate"`
}

type promptPayload struct {
	OverallScore int                 `json:"overall_score"`
	Routers      []promptRouterAudit `json:"routers"`
	Middlewares  []middlewareRef     `json:"middlewares,omitempty"`
	PulseAlerts  []promptPulseAlert  `json:"pulse_alerts,omitempty"`
}

type middlewareRef struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"`
}

// BuildContext serialises the audit into a slim JSON payload for the LLM.
// Drops the snapshot duplicate (RouterAudit already embeds Router) and
// trims fields the model does not reason about.
func BuildContext(
	report domain.AuditReport,
	snapshot domain.NetworkSnapshot,
	env string,
	knownMiddlewares []string,
	protectedIPs []string,
) string {
	payload := buildPromptPayload(report, snapshot)
	jsonBytes, _ := json.Marshal(payload) // compact, no indent

	middlewareList := "none configured"
	if len(knownMiddlewares) > 0 {
		middlewareList = strings.Join(knownMiddlewares, ", ")
	}

	protectedSection := ""
	if len(protectedIPs) > 0 {
		protectedSection = fmt.Sprintf("\nProtected IPs (NEVER block these — owner-confirmed trusted): %s\n",
			strings.Join(protectedIPs, ", "))
	}

	return fmt.Sprintf(`=== JANUS AUDIT SNAPSHOT ===
Environment: %s
Known Secure Middlewares: %s
Overall Score: %d / 100
Traefik Reachable: %v
Snapshot: %s%s
--- Audit (compact JSON) ---
%s
`,
		env,
		middlewareList,
		report.OverallScore,
		report.TraefikOK,
		report.GeneratedAt.Format("2006-01-02T15:04:05Z"),
		protectedSection,
		string(jsonBytes),
	)
}

// ContextHash returns a stable hash of the structural inputs the LLM cares
// about. Pulse error rates are excluded (they flap cycle-to-cycle); the set
// of services with active alerts IS included so a new bot scan still triggers
// a fresh analysis.
func ContextHash(report domain.AuditReport, snapshot domain.NetworkSnapshot) string {
	type hashInput struct {
		OverallScore       int
		Routers            []promptRouterAudit
		Middlewares        []middlewareRef
		ServicesWithAlerts []string
	}

	payload := buildPromptPayload(report, snapshot)
	services := make([]string, 0, len(payload.PulseAlerts))
	for _, a := range payload.PulseAlerts {
		services = append(services, a.ServiceName)
	}
	sort.Strings(services)

	h := sha256.New()
	_ = json.NewEncoder(h).Encode(hashInput{
		OverallScore:       payload.OverallScore,
		Routers:            payload.Routers,
		Middlewares:        payload.Middlewares,
		ServicesWithAlerts: services,
	})
	return hex.EncodeToString(h.Sum(nil))
}

func buildPromptPayload(report domain.AuditReport, snapshot domain.NetworkSnapshot) promptPayload {
	audits := make([]promptRouterAudit, 0, len(report.RouterAudits))
	for _, ra := range report.RouterAudits {
		if ra.Router.IsRedirect {
			continue // redirect-only routers are infrastructure noise
		}
		pr := promptRouter{
			Name:        ra.Router.Name,
			Rule:        ra.Router.Rule,
			Entrypoints: ra.Router.Entrypoints,
			Middlewares: ra.Router.Middlewares,
			HasTLS:      ra.Router.HasTLS,
			IsHTTPS:     ra.Router.IsHTTPS,
		}
		issues := make([]promptIssue, 0, len(ra.Issues))
		for _, is := range ra.Issues {
			issues = append(issues, promptIssue{
				Code:        is.Code,
				Description: is.Description,
				Severity:    is.Severity.String(),
			})
		}
		viols := make([]promptPolicyViolation, 0, len(ra.PolicyViolations))
		for _, pv := range ra.PolicyViolations {
			missing := make([]string, len(pv.Missing))
			for i, m := range pv.Missing {
				missing[i] = string(m)
			}
			viols = append(viols, promptPolicyViolation{
				PolicyName: pv.PolicyName,
				Pattern:    pv.Pattern,
				Missing:    missing,
			})
		}
		audits = append(audits, promptRouterAudit{
			Router:           pr,
			Score:            ra.Score,
			Issues:           issues,
			PolicyViolations: viols,
		})
	}
	sort.Slice(audits, func(i, j int) bool { return audits[i].Router.Name < audits[j].Router.Name })

	mws := make([]middlewareRef, 0, len(snapshot.Middlewares))
	for name, mw := range snapshot.Middlewares {
		mws = append(mws, middlewareRef{Name: name, Type: string(mw.Type)})
	}
	sort.Slice(mws, func(i, j int) bool { return mws[i].Name < mws[j].Name })

	pulses := make([]promptPulseAlert, 0, len(report.PulseAlerts))
	for _, p := range report.PulseAlerts {
		pulses = append(pulses, promptPulseAlert{ServiceName: p.ServiceName, ErrorRate: p.ErrorRate})
	}
	sort.Slice(pulses, func(i, j int) bool { return pulses[i].ServiceName < pulses[j].ServiceName })

	return promptPayload{
		OverallScore: report.OverallScore,
		Routers:      audits,
		Middlewares:  mws,
		PulseAlerts:  pulses,
	}
}

// ParseResponse converts the model's raw JSON reply into the internal DTO.
// Tolerant of leading/trailing prose and markdown fences — extracts the first
// balanced { … } block before attempting to unmarshal.
func ParseResponse(raw string) (*aiResponseDTO, error) {
	clean := ExtractJSONObject(raw)
	if clean == "" {
		return nil, fmt.Errorf("parse AI response JSON: no JSON object found in reply")
	}
	var dto aiResponseDTO
	if err := json.Unmarshal([]byte(clean), &dto); err != nil {
		return nil, fmt.Errorf("parse AI response JSON: %w", err)
	}
	return &dto, nil
}

// ExtractJSONObject returns the first top-level { … } block in s, ignoring
// braces inside JSON strings (and their escapes). Returns "" when no balanced
// object is found. Useful for stripping markdown fences, chain-of-thought
// preludes, or trailing prose that some LLMs add despite instructions.
func ExtractJSONObject(s string) string {
	start := -1
	depth := 0
	inString := false
	escape := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escape {
			escape = false
			continue
		}
		if inString {
			switch ch {
			case '\\':
				escape = true
			case '"':
				inString = false
			}
			continue
		}
		switch ch {
		case '"':
			inString = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					return s[start : i+1]
				}
			}
		}
	}
	return ""
}
