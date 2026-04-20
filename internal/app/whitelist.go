package app

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
)

// WhitelistService persists trusted IPs that the threat-intel AI should classify
// as LEGITIMATE regardless of traffic pattern.
type WhitelistService struct {
	path string
	mu   sync.RWMutex
	ips  map[string]struct{}
}

// NewWhitelistService loads the whitelist from path (creates empty if missing).
func NewWhitelistService(path string) *WhitelistService {
	s := &WhitelistService{path: path, ips: make(map[string]struct{})}
	_ = s.load()
	return s
}

func (s *WhitelistService) Add(ip string) error {
	s.mu.Lock()
	s.ips[ip] = struct{}{}
	s.mu.Unlock()
	return s.save()
}

func (s *WhitelistService) Remove(ip string) error {
	s.mu.Lock()
	delete(s.ips, ip)
	s.mu.Unlock()
	return s.save()
}

func (s *WhitelistService) Contains(ip string) bool {
	s.mu.RLock()
	_, ok := s.ips[ip]
	s.mu.RUnlock()
	return ok
}

func (s *WhitelistService) List() []string {
	s.mu.RLock()
	out := make([]string, 0, len(s.ips))
	for ip := range s.ips {
		out = append(out, ip)
	}
	s.mu.RUnlock()
	sort.Strings(out)
	return out
}

func (s *WhitelistService) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var ips []string
	if err := json.Unmarshal(data, &ips); err != nil {
		return err
	}
	s.mu.Lock()
	for _, ip := range ips {
		s.ips[ip] = struct{}{}
	}
	s.mu.Unlock()
	return nil
}

func (s *WhitelistService) save() error {
	list := s.List()
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}
