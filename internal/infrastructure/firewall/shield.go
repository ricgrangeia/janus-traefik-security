// Package firewall manages the Traefik dynamic-config YAML file that Janus
// uses to block attacker IPs via the ipAllowList middleware's excludedIPs strategy.
package firewall

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const middlewareName = "janus-shield"

// ShieldService manages a Traefik-compatible YAML file at a configurable path.
// It is safe for concurrent use.
type ShieldService struct {
	path string
	mu   sync.Mutex
}

// NewShieldService returns a ShieldService that manages the YAML file at path.
// The file (and parent directories) are created on the first write.
func NewShieldService(path string) *ShieldService {
	return &ShieldService{path: path}
}

// ListBlocked returns the IPs currently in the excludedIPs list.
func (s *ShieldService) ListBlocked() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readIPs()
}

// BlockIP adds ip to the excludedIPs list and rewrites the YAML file.
// Returns an error if ip is not a valid IP address or is already blocked.
func (s *ShieldService) BlockIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ips, err := s.readIPs()
	if err != nil {
		return err
	}
	for _, existing := range ips {
		if existing == ip {
			return nil // idempotent
		}
	}
	return s.write(append(ips, ip))
}

// UnblockIP removes ip from the excludedIPs list.
// Returns nil if the IP was not in the list (idempotent).
func (s *ShieldService) UnblockIP(ip string) error {
	ip = strings.TrimSpace(ip)

	s.mu.Lock()
	defer s.mu.Unlock()

	ips, err := s.readIPs()
	if err != nil {
		return err
	}
	filtered := ips[:0]
	for _, v := range ips {
		if v != ip {
			filtered = append(filtered, v)
		}
	}
	return s.write(filtered)
}

// readIPs parses blocked IPs from the YAML file.
// Returns nil slice (no error) if the file does not exist yet.
func (s *ShieldService) readIPs() ([]string, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("shield: read %s: %w", s.path, err)
	}
	return parseExcludedIPs(string(data)), nil
}

// write regenerates the full Traefik-compatible YAML from the given IP list.
func (s *ShieldService) write(ips []string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("shield: mkdir: %w", err)
	}

	var b strings.Builder
	b.WriteString("http:\n")
	b.WriteString("  middlewares:\n")
	b.WriteString("    " + middlewareName + ":\n")
	b.WriteString("      ipAllowList:\n")
	b.WriteString("        sourceRange:\n")
	b.WriteString("          - \"0.0.0.0/0\"\n")
	b.WriteString("        ipStrategy:\n")
	b.WriteString("          excludedIPs:\n")
	if len(ips) == 0 {
		b.WriteString("            [] # no IPs currently blocked\n")
	} else {
		for _, ip := range ips {
			fmt.Fprintf(&b, "            - \"%s\"\n", ip)
		}
	}

	if err := os.WriteFile(s.path, []byte(b.String()), 0o644); err != nil {
		return fmt.Errorf("shield: write %s: %w", s.path, err)
	}
	return nil
}

// parseExcludedIPs extracts IPs from the YAML format this service generates.
func parseExcludedIPs(yaml string) []string {
	var (
		ips     []string
		inBlock bool
	)
	for _, line := range strings.Split(yaml, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "excludedIPs:" {
			inBlock = true
			continue
		}
		if !inBlock {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") {
			ip := strings.Trim(strings.TrimPrefix(trimmed, "- "), `"`)
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
			}
		} else if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			break // end of the excludedIPs list
		}
	}
	return ips
}
