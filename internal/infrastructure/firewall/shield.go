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
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	gateName       = "janus-gate"            // forwardAuth middleware name
	adminListName  = "janus-admin-whitelist" // ipAllowList for admin-only routes
	historyWindow  = 24 * time.Hour          // window used for "blocks in last 24h" counting
	historyKeep    = 7 * 24 * time.Hour      // total history retention to survive restarts
	maxHistorySize = 10000                   // hard cap to prevent unbounded growth
)

// BlockConfig controls progressive block durations for automatic blocks.
// Manual blocks are always permanent regardless of this config.
type BlockConfig struct {
	BaseMin int // duration of the first auto-block of an IP in the 24h window
	StepMin int // additional minutes added per repeat offense in the same 24h window
	MaxMin  int // hard cap on a single block's duration
}

// DefaultBlockConfig returns 30 / 30 / 1440 — 30 min base, +30 per offense, cap 24h.
func DefaultBlockConfig() BlockConfig {
	return BlockConfig{BaseMin: 30, StepMin: 30, MaxMin: 24 * 60}
}

// BlockedEntry is the rich record stored for each currently blocked IP.
// ExpiresAt is nil for permanent (manual) blocks.
type BlockedEntry struct {
	IP          string     `json:"ip"`
	BlockedAt   time.Time  `json:"blocked_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	DurationMin int        `json:"duration_min,omitempty"` // 0 = permanent
	Source      string     `json:"source,omitempty"`       // "manual" | "auto" — informational
}

// IsPermanent reports whether the block has no expiry.
func (b BlockedEntry) IsPermanent() bool { return b.ExpiresAt == nil }

// Expired reports whether a non-permanent block has elapsed.
func (b BlockedEntry) Expired(now time.Time) bool {
	return b.ExpiresAt != nil && now.After(*b.ExpiresAt)
}

// historyEntry records one block event for the "Nth offense in 24h" calculation.
type historyEntry struct {
	IP          string    `json:"ip"`
	BlockedAt   time.Time `json:"blocked_at"`
	DurationMin int       `json:"duration_min"`
}

// ShieldService keeps an in-memory IP blocklist and writes two Traefik
// middlewares: janus-gate (forwardAuth → Janus /auth) and
// janus-admin-whitelist (ipAllowList for trusted admin IPs).
// Safe for concurrent use.
type ShieldService struct {
	middlewarePath string // path to Traefik dynamic-config YAML
	statePath      string // path to JSON state file (persisted across restarts)
	janusURL       string // internal URL Traefik uses to reach Janus

	mu        sync.RWMutex
	immunity  func(string) bool
	blocked   map[string]*BlockedEntry // IP → entry (also used for O(1) IsBlocked check)
	history   []historyEntry           // recent block events (auto-pruned to historyKeep window)
	adminList []string
	cfg       BlockConfig
}

// shieldState is the JSON schema for the persisted state file.
type shieldState struct {
	Blocked   []BlockedEntry `json:"blocked"`
	History   []historyEntry `json:"history,omitempty"`
	AdminList []string       `json:"admin_list"`
}

// legacyShieldState is the v0.x schema where blocked was a flat []string.
// Read-only — used for migration on first load.
type legacyShieldState struct {
	Blocked   []string `json:"blocked"`
	AdminList []string `json:"admin_list"`
}

// NewShieldService creates a ShieldService with the default block config,
// loads any persisted state (migrating from the legacy schema if needed),
// and writes the Traefik middleware config file.
func NewShieldService(middlewarePath, statePath, janusURL string) *ShieldService {
	s := &ShieldService{
		middlewarePath: middlewarePath,
		statePath:      statePath,
		janusURL:       strings.TrimRight(janusURL, "/"),
		blocked:        make(map[string]*BlockedEntry),
		cfg:            DefaultBlockConfig(),
	}
	s.loadState()
	if err := s.writeMiddlewareConfig(); err != nil {
		slog.Warn("shield: failed to write middleware config", "err", err)
	}
	return s
}

// WithBlockConfig overrides the default progressive-block timing.
func (s *ShieldService) WithBlockConfig(cfg BlockConfig) *ShieldService {
	if cfg.BaseMin < 1 {
		cfg.BaseMin = 30
	}
	if cfg.StepMin < 0 {
		cfg.StepMin = 0
	}
	if cfg.MaxMin < cfg.BaseMin {
		cfg.MaxMin = cfg.BaseMin
	}
	s.cfg = cfg
	return s
}

// WithImmunity attaches a lookup function. BlockIP will refuse to block any IP
// for which fn returns true.
func (s *ShieldService) WithImmunity(fn func(string) bool) *ShieldService {
	s.immunity = fn
	return s
}

// IsBlocked returns true if ip is currently blocked. Used by /auth on the hot path.
// Immunity is checked first — an IP that becomes immune after being blocked is
// treated as unblocked, preventing accidental lockouts.
func (s *ShieldService) IsBlocked(ip string) bool {
	if s.immunity != nil && s.immunity(ip) {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.blocked[ip]
	if !ok {
		return false
	}
	return !e.Expired(time.Now())
}

// ListBlocked returns just the IPs currently blocked. Convenience for callers
// that don't need the full entry (e.g. the ban-review worker).
func (s *ShieldService) ListBlocked() []string {
	entries := s.ListBlockedDetailed()
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.IP
	}
	return out
}

// ListBlockedDetailed returns the full BlockedEntry list, sorted by BlockedAt desc.
func (s *ShieldService) ListBlockedDetailed() []BlockedEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	out := make([]BlockedEntry, 0, len(s.blocked))
	for _, e := range s.blocked {
		if e.Expired(now) {
			continue
		}
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BlockedAt.After(out[j].BlockedAt) })
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

// BlockIP adds ip to the blocklist permanently — no expiry. Used by manual
// blocks from the dashboard/API. Idempotent: re-blocking an already-blocked
// IP becomes a no-op (it stays whatever it was).
func (s *ShieldService) BlockIP(ip string) error {
	return s.blockInternal(ip, "manual", 0)
}

// BlockIPAuto adds ip with a progressive duration based on its block history
// in the last 24h. Returns the duration applied (in minutes) and the offense
// count (1 = first block in 24h, 2 = second, …). Returns (0, 0, err) on failure.
func (s *ShieldService) BlockIPAuto(ip string) (durationMin int, offenseCount int, err error) {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return 0, 0, fmt.Errorf("invalid IP address: %q", ip)
	}
	if s.immunity != nil && s.immunity(ip) {
		slog.Info("[IMMUNITY] Prevented ban of protected IP", "ip", ip)
		return 0, 0, fmt.Errorf("IP %s is protected and cannot be blocked", ip)
	}

	s.mu.Lock()
	// Count prior blocks of this IP in the last 24h (excluding any current entry).
	cutoff := time.Now().Add(-historyWindow)
	prior := 0
	for _, h := range s.history {
		if h.IP == ip && h.BlockedAt.After(cutoff) {
			prior++
		}
	}
	offenseCount = prior + 1
	durationMin = s.cfg.BaseMin + s.cfg.StepMin*prior
	if durationMin > s.cfg.MaxMin {
		durationMin = s.cfg.MaxMin
	}
	s.mu.Unlock()

	if err := s.blockInternal(ip, "auto", durationMin); err != nil {
		return 0, 0, err
	}
	return durationMin, offenseCount, nil
}

// blockInternal is the shared block path. durationMin=0 means permanent.
// Caller must NOT hold s.mu — this function takes the lock.
func (s *ShieldService) blockInternal(ip, source string, durationMin int) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}
	if s.immunity != nil && s.immunity(ip) {
		slog.Info("[IMMUNITY] Prevented ban of protected IP", "ip", ip)
		return fmt.Errorf("IP %s is protected and cannot be blocked", ip)
	}

	now := time.Now().UTC()
	entry := &BlockedEntry{
		IP:          ip,
		BlockedAt:   now,
		DurationMin: durationMin,
		Source:      source,
	}
	if durationMin > 0 {
		exp := now.Add(time.Duration(durationMin) * time.Minute)
		entry.ExpiresAt = &exp
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.blocked[ip]; ok && !existing.Expired(now) {
		return nil // idempotent — already blocked and still active
	}
	s.blocked[ip] = entry
	s.history = append(s.history, historyEntry{IP: ip, BlockedAt: now, DurationMin: durationMin})
	s.pruneHistoryLocked()
	return s.saveState()
}

// UnblockIP removes ip from the blocklist. Idempotent. Returns true if an
// entry was actually removed (so callers can decide whether to fire an alert).
func (s *ShieldService) UnblockIP(ip string) error {
	_, err := s.unblockInternal(ip)
	return err
}

// unblockInternal returns whether anything was removed plus any save error.
func (s *ShieldService) unblockInternal(ip string) (removed bool, err error) {
	ip = strings.TrimSpace(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.blocked[ip]; !ok {
		return false, nil
	}
	delete(s.blocked, ip)
	return true, s.saveState()
}

// PurgeExpired removes any entries whose ExpiresAt has passed. Returns the
// list of IPs that were actually unblocked, so the caller can notify.
func (s *ShieldService) PurgeExpired() []string {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var expired []string
	for ip, e := range s.blocked {
		if e.Expired(now) {
			expired = append(expired, ip)
			delete(s.blocked, ip)
		}
	}
	if len(expired) > 0 {
		if err := s.saveState(); err != nil {
			slog.Warn("shield: failed to save state after purge", "err", err)
		}
	}
	return expired
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

// pruneHistoryLocked drops history entries older than historyKeep, and caps
// the total size at maxHistorySize. Caller must hold s.mu.
func (s *ShieldService) pruneHistoryLocked() {
	cutoff := time.Now().Add(-historyKeep)
	filtered := s.history[:0]
	for _, h := range s.history {
		if h.BlockedAt.After(cutoff) {
			filtered = append(filtered, h)
		}
	}
	if len(filtered) > maxHistorySize {
		filtered = filtered[len(filtered)-maxHistorySize:]
	}
	s.history = filtered
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
	// Try the rich schema first; if blocked entries aren't objects, fall back to
	// the legacy []string format and migrate.
	var st shieldState
	if err := json.Unmarshal(data, &st); err == nil && (len(st.Blocked) == 0 || st.Blocked[0].IP != "") {
		s.adminList = st.AdminList
		s.history = st.History
		now := time.Now()
		for i := range st.Blocked {
			e := st.Blocked[i]
			if e.Expired(now) {
				continue // skip already-expired entries
			}
			s.blocked[e.IP] = &e
		}
		slog.Info("shield: state loaded", "blocked", len(s.blocked), "admin_list", len(s.adminList), "history", len(s.history))
		return
	}
	// Legacy migration.
	var legacy legacyShieldState
	if err := json.Unmarshal(data, &legacy); err != nil {
		slog.Warn("shield: parse state", "err", err)
		return
	}
	s.adminList = legacy.AdminList
	now := time.Now().UTC()
	for _, ip := range legacy.Blocked {
		s.blocked[ip] = &BlockedEntry{
			IP:        ip,
			BlockedAt: now,
			Source:    "manual",
		}
	}
	slog.Info("shield: state migrated from legacy schema", "blocked", len(s.blocked), "admin_list", len(s.adminList))
	if err := s.saveState(); err != nil {
		slog.Warn("shield: failed to persist migrated state", "err", err)
	}
}

func (s *ShieldService) saveState() error {
	st := shieldState{
		Blocked:   make([]BlockedEntry, 0, len(s.blocked)),
		History:   s.history,
		AdminList: s.adminList,
	}
	for _, e := range s.blocked {
		st.Blocked = append(st.Blocked, *e)
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
