// Package firewall manages the Traefik dynamic-config YAML file that Janus
// uses to block attacker IPs via the ipAllowList middleware's excludedIPs strategy,
// and the admin allowlist that restricts specific routes to trusted IPs only.
package firewall

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	middlewareName      = "janus-shield"
	adminMiddlewareName = "janus-admin-whitelist"
)

// ShieldService manages a Traefik-compatible YAML file at a configurable path.
// It is safe for concurrent use.
type ShieldService struct {
	path     string
	mu       sync.Mutex
	immunity func(string) bool // optional: returns true for IPs that must never be blocked
}

// NewShieldService returns a ShieldService that manages the YAML file at path.
// The file (and parent directories) are created on the first write.
func NewShieldService(path string) *ShieldService {
	return &ShieldService{path: path}
}

// WithImmunity attaches a lookup function. BlockIP will refuse to block any IP
// for which fn returns true, logging the attempt instead.
func (s *ShieldService) WithImmunity(fn func(string) bool) *ShieldService {
	s.immunity = fn
	return s
}

// ListBlocked returns the IPs currently in the excludedIPs (global block) list.
func (s *ShieldService) ListBlocked() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.readState()
	return st.blocked, err
}

// GetAdminWhitelist returns the IPs currently in the janus-admin-whitelist sourceRange.
func (s *ShieldService) GetAdminWhitelist() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.readState()
	return st.adminList, err
}

// BlockIP adds ip to the global excludedIPs list and rewrites the YAML file.
// Returns an error if ip is not valid, already blocked, or is immune.
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

	st, err := s.readState()
	if err != nil {
		return err
	}
	for _, existing := range st.blocked {
		if existing == ip {
			return nil // idempotent
		}
	}
	st.blocked = append(st.blocked, ip)
	return s.write(st)
}

// UnblockIP removes ip from the global excludedIPs list.
// Returns nil if the IP was not in the list (idempotent).
func (s *ShieldService) UnblockIP(ip string) error {
	ip = strings.TrimSpace(ip)

	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.readState()
	if err != nil {
		return err
	}
	filtered := st.blocked[:0]
	for _, v := range st.blocked {
		if v != ip {
			filtered = append(filtered, v)
		}
	}
	st.blocked = filtered
	return s.write(st)
}

// AddAdminIP adds ip to the janus-admin-whitelist sourceRange.
func (s *ShieldService) AddAdminIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.readState()
	if err != nil {
		return err
	}
	for _, existing := range st.adminList {
		if existing == ip {
			return nil // idempotent
		}
	}
	st.adminList = append(st.adminList, ip)
	return s.write(st)
}

// RemoveAdminIP removes ip from the janus-admin-whitelist sourceRange.
func (s *ShieldService) RemoveAdminIP(ip string) error {
	ip = strings.TrimSpace(ip)

	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.readState()
	if err != nil {
		return err
	}
	filtered := st.adminList[:0]
	for _, v := range st.adminList {
		if v != ip {
			filtered = append(filtered, v)
		}
	}
	st.adminList = filtered
	return s.write(st)
}

// ── Internal state ────────────────────────────────────────────────────────────

type shieldState struct {
	blocked   []string // janus-shield excludedIPs
	adminList []string // janus-admin-whitelist sourceRange
}

func (s *ShieldService) readState() (shieldState, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return shieldState{}, nil
	}
	if err != nil {
		return shieldState{}, fmt.Errorf("shield: read %s: %w", s.path, err)
	}
	return parseShieldYAML(string(data)), nil
}

func (s *ShieldService) write(st shieldState) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("shield: mkdir: %w", err)
	}

	var b strings.Builder
	b.WriteString("http:\n")
	b.WriteString("  middlewares:\n")

	// Global block list — sourceRange allows all, excludedIPs deny the attackers.
	b.WriteString("    " + middlewareName + ":\n")
	b.WriteString("      ipAllowList:\n")
	b.WriteString("        sourceRange:\n")
	b.WriteString("          - \"0.0.0.0/0\"\n")
	b.WriteString("        ipStrategy:\n")
	b.WriteString("          excludedIPs:\n")
	if len(st.blocked) == 0 {
		b.WriteString("            [] # no IPs currently blocked\n")
	} else {
		for _, ip := range st.blocked {
			fmt.Fprintf(&b, "            - \"%s\"\n", ip)
		}
	}

	// Admin allowlist — sourceRange restricts access to trusted IPs only.
	if len(st.adminList) > 0 {
		b.WriteString("    " + adminMiddlewareName + ":\n")
		b.WriteString("      ipAllowList:\n")
		b.WriteString("        sourceRange:\n")
		for _, ip := range st.adminList {
			fmt.Fprintf(&b, "          - \"%s\"\n", ip)
		}
	}

	if err := os.WriteFile(s.path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("shield: write %s: %w", s.path, err)
	}
	return nil
}

// ── YAML parser ───────────────────────────────────────────────────────────────

func parseShieldYAML(yaml string) shieldState {
	var st shieldState

	type curList int
	const (
		listNone           curList = iota
		listShieldExcluded         // janus-shield → excludedIPs
		listAdminSource            // janus-admin-whitelist → sourceRange
	)

	cur := listNone
	inAdmin := false

	for _, line := range strings.Split(yaml, "\n") {
		trimmed := strings.TrimSpace(line)

		switch trimmed {
		case middlewareName + ":":
			inAdmin = false
			cur = listNone
		case adminMiddlewareName + ":":
			inAdmin = true
			cur = listNone
		case "excludedIPs:":
			if !inAdmin {
				cur = listShieldExcluded
			}
		case "sourceRange:":
			if inAdmin {
				cur = listAdminSource
			}
		default:
			if strings.HasPrefix(trimmed, "- ") {
				ip := strings.Trim(strings.TrimPrefix(trimmed, "- "), `"`)
				if net.ParseIP(ip) != nil {
					switch cur {
					case listShieldExcluded:
						st.blocked = append(st.blocked, ip)
					case listAdminSource:
						st.adminList = append(st.adminList, ip)
					}
				}
			} else if trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "[]") {
				cur = listNone
			}
		}
	}
	return st
}
