package app

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/janus-project/janus/internal/infrastructure/geoip"
	"github.com/janus-project/janus/internal/infrastructure/llm"
	"github.com/janus-project/janus/internal/infrastructure/logs"
)

// ── Domain types ─────────────────────────────────────────────────────────────

// IPProfile combines traffic stats with geographic, ASN, and AI classification data.
type IPProfile struct {
	IP             string
	CountryCode    string
	CountryName    string
	City           string
	ASN            uint   // autonomous-system number
	Organization   string // ASN org name (e.g. "Amazon.com, Inc.", "Hetzner Online GmbH")
	Total          int
	Count2xx       int
	Count4xx       int
	Count5xx       int
	ErrorRate      float64
	TopRouter      string
	TopPaths       []string // up to 3 most-hit paths, formatted "path (count)"
	TopStatuses    []string // up to 3 status codes, formatted "code:count"
	TopUserAgents  []string // up to 2 most-seen UAs
	Classification string   // "HOSTILE" | "SUSPICIOUS" | "LEGITIMATE" | "UNKNOWN"
	Reasoning      string
}

// HostileCluster groups IPs sharing the same attack pattern.
type HostileCluster struct {
	Description   string
	IPs           []string
	TargetPattern string
}

// AttackerNation summarises threat activity from one country.
type AttackerNation struct {
	CountryCode string
	CountryName string
	IPCount     int
	ThreatLevel string
}

// ThreatIntelReport is the output of one full intelligence analysis cycle.
type ThreatIntelReport struct {
	TopIPs          []IPProfile
	HostileClusters []HostileCluster
	AttackerNations []AttackerNation
	LegitimateIPs   []string
	Summary         string
	UniqueIPs       int
	GeneratedAt     time.Time
	TokensUsed      int
	LatencyMs       int64
}

// ── Service ──────────────────────────────────────────────────────────────────

// ThreatIntelService orchestrates the traffic analyzer, geo lookups, and AI
// threat profiling into a single on-demand or periodic intelligence report.
type ThreatIntelService struct {
	analyzer  *logs.TrafficAnalyzer
	geo       *geoip.Reader
	asn       *geoip.ASNReader // optional — nil when no ASN db is configured
	client    *llm.Client
	whitelist *WhitelistService // optional — nil means no trusted IPs configured

	mu      sync.RWMutex
	latest  *ThreatIntelReport
	running bool // guard against concurrent analysis
}

// NewThreatIntelService creates the service. analyzer, geo, and client are required.
func NewThreatIntelService(
	analyzer *logs.TrafficAnalyzer,
	geo *geoip.Reader,
	client *llm.Client,
) *ThreatIntelService {
	return &ThreatIntelService{
		analyzer: analyzer,
		geo:      geo,
		client:   client,
	}
}

// WithASN attaches an ASN reader. When set, IP profiles include the operating
// organisation, which materially improves the LLM's ability to distinguish
// crawler/monitoring traffic from genuine attackers.
func (s *ThreatIntelService) WithASN(r *geoip.ASNReader) *ThreatIntelService {
	s.asn = r
	return s
}

// WithWhitelist attaches a trusted-IP whitelist. Whitelisted IPs are passed to
// the AI as known-good so they are not misclassified as hostile.
func (s *ThreatIntelService) WithWhitelist(w *WhitelistService) *ThreatIntelService {
	s.whitelist = w
	return s
}

// LatestReport returns the most recent report, or nil if Analyze has not run yet.
func (s *ThreatIntelService) LatestReport() *ThreatIntelReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latest
}

// AnalyzeAsync starts a fresh analysis in the background. Returns immediately.
// If an analysis is already running, this call is a no-op.
func (s *ThreatIntelService) AnalyzeAsync() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
		}()
		if err := s.analyze(); err != nil {
			slog.Info("threat intel analysis skipped", "reason", err)
		}
	}()
}

func (s *ThreatIntelService) analyze() error {
	start := time.Now()
	topStats := s.analyzer.TopIPs(20)
	if len(topStats) == 0 {
		return fmt.Errorf("no traffic data yet — access log may be empty or not configured")
	}

	// Enrich with geo + ASN + per-IP fingerprint.
	profiles := make([]IPProfile, 0, len(topStats))
	for _, stat := range topStats {
		meta := s.geo.Lookup(stat.IP)
		var asn geoip.ASNInfo
		if s.asn != nil {
			asn = s.asn.Lookup(stat.IP)
		}
		paths := make([]string, 0, len(stat.TopPaths))
		for _, p := range stat.TopPaths {
			paths = append(paths, fmt.Sprintf("%s (%d)", p.Key, p.Count))
		}
		statuses := make([]string, 0, len(stat.TopStatuses))
		for _, s := range stat.TopStatuses {
			statuses = append(statuses, fmt.Sprintf("%d:%d", s.Code, s.Count))
		}
		uas := make([]string, 0, len(stat.TopUserAgents))
		for _, ua := range stat.TopUserAgents {
			uas = append(uas, ua.Key)
		}
		profiles = append(profiles, IPProfile{
			IP:            stat.IP,
			CountryCode:   meta.CountryCode,
			CountryName:   meta.CountryName,
			City:          meta.City,
			ASN:           asn.ASN,
			Organization:  asn.Organization,
			Total:         stat.Total,
			Count2xx:      stat.Count2xx,
			Count4xx:      stat.Count4xx,
			Count5xx:      stat.Count5xx,
			ErrorRate:     stat.ErrorRate,
			TopRouter:     stat.TopRouter,
			TopPaths:      paths,
			TopStatuses:   statuses,
			TopUserAgents: uas,
		})
	}

	var trustedIPs []string
	if s.whitelist != nil {
		trustedIPs = s.whitelist.List()
	}
	ctx := buildIntelContext(profiles, s.analyzer.UniqueIPCount(), trustedIPs)
	reply, usage, err := s.client.Chat(llm.IntelSystemPrompt, ctx)
	if err != nil {
		return fmt.Errorf("LLM intel: %w", err)
	}

	report, err := parseIntelResponse(reply, profiles)
	if err != nil {
		return fmt.Errorf("parse intel response: %w", err)
	}
	report.UniqueIPs = s.analyzer.UniqueIPCount()
	report.GeneratedAt = time.Now().UTC()
	report.TokensUsed = usage.TotalTokens
	report.LatencyMs = time.Since(start).Milliseconds()

	slog.Info("threat intel analysis complete",
		"top_ips", len(report.TopIPs),
		"hostile_clusters", len(report.HostileClusters),
		"tokens", report.TokensUsed,
		"latency_ms", report.LatencyMs,
	)

	s.mu.Lock()
	s.latest = report
	s.mu.Unlock()
	return nil
}

// MarkdownReport generates a downloadable Markdown threat report from the latest data.
func (s *ThreatIntelService) MarkdownReport() string {
	s.mu.RLock()
	r := s.latest
	s.mu.RUnlock()
	if r == nil {
		return "# Janus Threat Intelligence Report\n\nNo analysis has been run yet.\n"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Janus Threat Intelligence Report\n\n")
	fmt.Fprintf(&b, "**Generated:** %s  \n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "**Analysis window:** Last 1 hour  \n")
	fmt.Fprintf(&b, "**Unique IPs tracked:** %d  \n\n", r.UniqueIPs)
	b.WriteString("---\n\n")

	if r.Summary != "" {
		b.WriteString("## Executive Summary\n\n")
		b.WriteString(r.Summary)
		b.WriteString("\n\n---\n\n")
	}

	if len(r.TopIPs) > 0 {
		b.WriteString("## Top Attackers\n\n")
		b.WriteString("| IP | Country | City | Total Hits | Error % | Classification |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, ip := range r.TopIPs {
			flag := countryFlag(ip.CountryCode)
			b.WriteString(fmt.Sprintf("| `%s` | %s %s | %s | %d | %.1f%% | %s |\n",
				ip.IP, flag, ip.CountryName, ip.City, ip.Total, ip.ErrorRate*100, ip.Classification,
			))
		}
		b.WriteString("\n---\n\n")
	}

	if len(r.HostileClusters) > 0 {
		b.WriteString("## Hostile Clusters\n\n")
		for i, c := range r.HostileClusters {
			fmt.Fprintf(&b, "### Cluster %d\n", i+1)
			fmt.Fprintf(&b, "**Description:** %s  \n", c.Description)
			fmt.Fprintf(&b, "**Target:** %s  \n", c.TargetPattern)
			fmt.Fprintf(&b, "**IPs:** %s  \n\n", strings.Join(c.IPs, ", "))
		}
		b.WriteString("---\n\n")
	}

	if len(r.AttackerNations) > 0 {
		b.WriteString("## Attacker Nations\n\n")
		b.WriteString("| Country | IP Count | Threat Level |\n")
		b.WriteString("|---|---|---|\n")
		for _, n := range r.AttackerNations {
			flag := countryFlag(n.CountryCode)
			fmt.Fprintf(&b, "| %s %s | %d | %s |\n", flag, n.CountryName, n.IPCount, n.ThreatLevel)
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n*Report generated by Janus-AI*\n")
	return b.String()
}

// ── Context builder ───────────────────────────────────────────────────────────

func buildIntelContext(profiles []IPProfile, totalUnique int, trustedIPs []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== TRAFFIC INTELLIGENCE SNAPSHOT ===\n")
	fmt.Fprintf(&b, "Analysis window: last 1 hour\n")
	fmt.Fprintf(&b, "Total unique IPs tracked: %d\n", totalUnique)
	if len(trustedIPs) > 0 {
		fmt.Fprintf(&b, "Trusted IPs (owner-confirmed — classify as LEGITIMATE): %s\n",
			strings.Join(trustedIPs, ", "))
	}
	b.WriteString("\nClassification guidance:\n")
	b.WriteString("- Cloud providers (AWS, GCP, Azure, Hetzner, Datacamp, Linode, OVH, DigitalOcean) with moderate error rates and normal-looking paths are usually crawlers/monitoring — NOT hostile.\n")
	b.WriteString("- 100% error rate on non-existent admin paths (/wp-admin, /.env, /.git, /phpmyadmin) is unambiguous bot scanning.\n")
	b.WriteString("- bot/crawler/monitoring user-agents (UptimeRobot, Pingdom, GoogleBot, bingbot, ahrefsbot) are LEGITIMATE.\n")
	b.WriteString("- Empty/scripted UAs (python-requests, curl, Go-http-client, libwww-perl) combined with high error rate suggest probing.\n")
	b.WriteString("- IPs from the same /24 hitting the same router with the same pattern are ONE cluster — give them the same verdict.\n\n")

	for i, p := range profiles {
		fmt.Fprintf(&b, "[%d] %s — %s, %s (%s) — ASN %d %s\n",
			i+1, p.IP, p.City, p.CountryName, p.CountryCode, p.ASN, p.Organization)
		fmt.Fprintf(&b, "    Hits: %d (2xx=%d 4xx=%d 5xx=%d, err%%=%.1f) | Top router: %s\n",
			p.Total, p.Count2xx, p.Count4xx, p.Count5xx, p.ErrorRate*100, p.TopRouter)
		if len(p.TopPaths) > 0 {
			fmt.Fprintf(&b, "    Paths: %s\n", strings.Join(p.TopPaths, " | "))
		}
		if len(p.TopStatuses) > 0 {
			fmt.Fprintf(&b, "    Status codes: %s\n", strings.Join(p.TopStatuses, " "))
		}
		if len(p.TopUserAgents) > 0 {
			fmt.Fprintf(&b, "    User-agent: %s\n", strings.Join(p.TopUserAgents, " | "))
		}
		b.WriteString("\n")
	}
	return b.String()
}

// ── Response parser ───────────────────────────────────────────────────────────

type intelResponseDTO struct {
	HostileClusters []struct {
		Description   string   `json:"description"`
		IPs           []string `json:"ips"`
		TargetPattern string   `json:"target_pattern"`
	} `json:"hostile_clusters"`
	LegitimateIPs   []string `json:"legitimate_ips"`
	AttackerNations []struct {
		CountryCode string `json:"country_code"`
		CountryName string `json:"country_name"`
		IPCount     int    `json:"ip_count"`
		ThreatLevel string `json:"threat_level"`
	} `json:"attacker_nations"`
	IPClassifications map[string]struct {
		Verdict   string `json:"verdict"`
		Reasoning string `json:"reasoning"`
	} `json:"ip_classifications"`
	Summary string `json:"summary"`
}

func parseIntelResponse(raw string, profiles []IPProfile) (*ThreatIntelReport, error) {
	clean := llm.ExtractJSONObject(raw)
	if clean == "" {
		return nil, fmt.Errorf("JSON parse: no JSON object found in LLM reply")
	}

	var dto intelResponseDTO
	if err := json.Unmarshal([]byte(clean), &dto); err != nil {
		return nil, fmt.Errorf("JSON parse: %w", err)
	}

	// Overlay AI classifications onto profiles.
	enriched := make([]IPProfile, len(profiles))
	copy(enriched, profiles)
	for i, p := range enriched {
		if c, ok := dto.IPClassifications[p.IP]; ok {
			enriched[i].Classification = c.Verdict
			enriched[i].Reasoning = c.Reasoning
		}
		if enriched[i].Classification == "" {
			enriched[i].Classification = "UNKNOWN"
		}
	}

	report := &ThreatIntelReport{
		TopIPs:        enriched,
		LegitimateIPs: dto.LegitimateIPs,
		Summary:       dto.Summary,
	}
	for _, c := range dto.HostileClusters {
		report.HostileClusters = append(report.HostileClusters, HostileCluster{
			Description:   c.Description,
			IPs:           c.IPs,
			TargetPattern: c.TargetPattern,
		})
	}
	for _, n := range dto.AttackerNations {
		report.AttackerNations = append(report.AttackerNations, AttackerNation{
			CountryCode: n.CountryCode,
			CountryName: n.CountryName,
			IPCount:     n.IPCount,
			ThreatLevel: n.ThreatLevel,
		})
	}
	return report, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// countryFlag converts an ISO 3166-1 alpha-2 code to the Unicode flag emoji.
func countryFlag(code string) string {
	if len(code) != 2 {
		return "🌐"
	}
	a := rune(code[0]-'A') + 0x1F1E6
	b := rune(code[1]-'A') + 0x1F1E6
	return string([]rune{a, b})
}
