// Package firewall manages Janus's active-defense layer.
// It keeps an in-memory IP blocklist (persisted as JSON) and writes a
// Traefik dynamic-config YAML with a forwardAuth middleware so that every
// request passes through Janus's /auth endpoint before reaching the backend.
// No iptables, no root required — pure Docker/Traefik layer.
package firewall

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	gateName      = "janus-gate"           // forwardAuth middleware name
	adminListName = "janus-admin-whitelist" // ipAllowList for admin-only routes
)

// ShieldService keeps an in-memory IP blocklist and writes two Traefik
// middlewares: janus-gate (forwardAuth → Janus /auth) and
// janus-admin-whitelist (ipAllowList for trusted admin IPs).
// Safe for concurrent use.
type ShieldService struct {
	middlewarePath string // path to Traefik dynamic-config YAML (written at startup + on admin list change)
	statePath      string // path to JSON state file (persisted across restarts)
	janusURL       string // internal URL Traefik uses to reach Janus, e.g. http://janus:9090

	mu         sync.RWMutex
	immunity   func(string) bool
	blocked    []string        // ordered list for API responses
	blockedSet map[string]bool // O(1) lookup for /auth hot path
	adminList  []string
}

// shieldState is the JSON schema for the persisted state file.
type shieldState struct {
	Blocked   []string `json:"blocked"`
	AdminList []string `json:"admin_list"`
}

// NewShieldService creates a ShieldService, loads any persisted state, and
// writes the Traefik middleware config file.
func NewShieldService(middlewarePath, statePath, janusURL string) *ShieldService {
	s := &ShieldService{
		middlewarePath: middlewarePath,
		statePath:      statePath,
		janusURL:       strings.TrimRight(janusURL, "/"),
		blockedSet:     make(map[string]bool),
	}
	s.loadState()
	if err := s.writeMiddlewareConfig(); err != nil {
		slog.Warn("shield: failed to write middleware config", "err", err)
	}
	return s
}

// WithImmunity attaches a lookup function. BlockIP will refuse to block any IP
// for which fn returns true.
func (s *ShieldService) WithImmunity(fn func(string) bool) *ShieldService {
	s.immunity = fn
	return s
}

// IsBlocked returns true if ip is currently blocked. O(1). Used by /auth.
// Immunity is checked first — an IP that becomes immune after being blocked
// is treated as unblocked on the hot path, preventing accidental lockouts.
func (s *ShieldService) IsBlocked(ip string) bool {
	if s.immunity != nil && s.immunity(ip) {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blockedSet[ip]
}

// ListBlocked returns a snapshot of all currently blocked IPs.
func (s *ShieldService) ListBlocked() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.blocked))
	copy(out, s.blocked)
	return out
}

// GetAdminWhitelist returns a snapshot of the admin allowlist.
func (s *ShieldService) GetAdminWhitelist() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.adminList))
	copy(out, s.adminList)
	return out
}

// BlockIP adds ip to the blocklist. Idempotent. Returns an error if the IP is
// invalid, immune, or (no-op) already blocked.
func (s *ShieldService) BlockIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}
	if s.immunity != nil && s.immunity(ip) {
		slog.Info("[IMMUNITY] Prevented ban of protected IP", "ip", ip)
		return fmt.Errorf("IP %s is protected and cannot be blocked", ip)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.blockedSet[ip] {
		return nil
	}
	s.blocked = append(s.blocked, ip)
	s.blockedSet[ip] = true
	return s.saveState()
}

// UnblockIP removes ip from the blocklist. Idempotent.
func (s *ShieldService) UnblockIP(ip string) error {
	ip = strings.TrimSpace(ip)

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.blockedSet[ip] {
		return nil
	}
	filtered := make([]string, 0, len(s.blocked)-1)
	for _, v := range s.blocked {
		if v != ip {
			filtered = append(filtered, v)
		}
	}
	s.blocked = filtered
	delete(s.blockedSet, ip)
	return s.saveState()
}

// AddAdminIP adds ip to the admin allowlist and rewrites the Traefik YAML.
func (s *ShieldService) AddAdminIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.adminList {
		if existing == ip {
			return nil
		}
	}
	s.adminList = append(s.adminList, ip)
	if err := s.saveState(); err != nil {
		return err
	}
	return s.writeMiddlewareConfig()
}

// RemoveAdminIP removes ip from the admin allowlist and rewrites the Traefik YAML.
func (s *ShieldService) RemoveAdminIP(ip string) error {
	ip = strings.TrimSpace(ip)

	s.mu.Lock()
	defer s.mu.Unlock()

	filtered := make([]string, 0, len(s.adminList))
	for _, v := range s.adminList {
		if v != ip {
			filtered = append(filtered, v)
		}
	}
	s.adminList = filtered
	if err := s.saveState(); err != nil {
		return err
	}
	return s.writeMiddlewareConfig()
}

// ── Internal ──────────────────────────────────────────────────────────────────

func (s *ShieldService) loadState() {
	data, err := os.ReadFile(s.statePath)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		slog.Warn("shield: load state", "path", s.statePath, "err", err)
		return
	}
	var st shieldState
	if err := json.Unmarshal(data, &st); err != nil {
		slog.Warn("shield: parse state", "err", err)
		return
	}
	s.blocked = st.Blocked
	s.adminList = st.AdminList
	for _, ip := range st.Blocked {
		s.blockedSet[ip] = true
	}
	slog.Info("shield: state loaded", "blocked", len(s.blocked), "admin_list", len(s.adminList))
}

func (s *ShieldService) saveState() error {
	st := shieldState{
		Blocked:   s.blocked,
		AdminList: s.adminList,
	}
	if st.Blocked == nil {
		st.Blocked = []string{}
	}
	if st.AdminList == nil {
		st.AdminList = []string{}
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("shield: marshal state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0o755); err != nil {
		return fmt.Errorf("shield: mkdir state: %w", err)
	}
	if err := os.WriteFile(s.statePath, data, 0o644); err != nil {
		return fmt.Errorf("shield: write state %s: %w", s.statePath, err)
	}
	return nil
}

// writeMiddlewareConfig writes the Traefik dynamic-config YAML.
// Called at startup and whenever the admin list changes.
// Caller must hold s.mu or be in a single-goroutine context.
func (s *ShieldService) writeMiddlewareConfig() error {
	if s.middlewarePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.middlewarePath), 0o755); err != nil {
		return fmt.Errorf("shield: mkdir middleware: %w", err)
	}

	var b strings.Builder
	b.WriteString("http:\n")
	b.WriteString("  middlewares:\n")

	// janus-gate — forwardAuth: Janus is the gatekeeper, no root needed.
	b.WriteString("    " + gateName + ":\n")
	b.WriteString("      forwardAuth:\n")
	fmt.Fprintf(&b, "        address: \"%s/auth\"\n", s.janusURL)
	b.WriteString("        trustForwardHeader: true\n")

	// janus-admin-whitelist — ipAllowList correctly used as an allowlist
	// (default deny, explicit allow) for admin-only routes like Portainer.
	if len(s.adminList) > 0 {
		b.WriteString("    " + adminListName + ":\n")
		b.WriteString("      ipAllowList:\n")
		b.WriteString("        sourceRange:\n")
		for _, ip := range s.adminList {
			fmt.Fprintf(&b, "          - \"%s\"\n", ip)
		}
	}

	if err := os.WriteFile(s.middlewarePath, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("shield: write middleware config %s: %w", s.middlewarePath, err)
	}
	slog.Info("shield: middleware config written", "path", s.middlewarePath, "gate", s.janusURL+"/auth")
	return nil
}
