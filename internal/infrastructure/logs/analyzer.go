package logs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"
)

// IPStats aggregates access patterns for a single IP over the retention window.
type IPStats struct {
	IP            string
	Total         int
	Count2xx      int
	Count4xx      int
	Count5xx      int
	ErrorRate     float64 // (4xx+5xx) / total
	TopRouter     string
	TopPaths      []KVCount  // up to 3 most-hit paths
	TopStatuses   []IntCount // status code histogram, top 3
	TopUserAgents []KVCount  // up to 2 most-seen UAs
	LastSeen      time.Time
}

// KVCount is a (string, count) tuple used for top-N histograms in IPStats.
type KVCount struct {
	Key   string
	Count int
}

// IntCount is a (int, count) tuple used for status-code histograms in IPStats.
type IntCount struct {
	Code  int
	Count int
}

// ErrorSample is one 4xx/5xx request captured for diagnostic display.
type ErrorSample struct {
	Status int       `json:"Status"`
	Method string    `json:"Method"`
	Path   string    `json:"Path"`
	Time   time.Time `json:"Time"`
}

// analyzerEntry mirrors all fields Janus reads from the Traefik access log.
type analyzerEntry struct {
	ClientAddr       string `json:"ClientAddr"`
	DownstreamStatus int    `json:"DownstreamStatus"`
	RequestPath      string `json:"RequestPath"`
	RequestMethod    string `json:"RequestMethod"`
	RouterName       string `json:"RouterName"`
	StartUTC         string `json:"StartUTC"`
	Time             string `json:"time"`
	UserAgent        string `json:"request_User-Agent"`
}

const (
	retentionPeriod          = time.Hour
	maxErrorSamplesPerIP     = 100  // ring-buffer cap
	maxPathsPerIP            = 64   // bounded map cap — new keys ignored past this
	maxUserAgentsPerIP       = 16
	maxUserAgentLen          = 120  // truncate to avoid memory blowup from long UAs
	analyzerMaxTrackedIPs    = 5000 // hard cap; LRU eviction beyond this protects against bot-scan memory blow-up
)

type ipCounter struct {
	total      int
	count2xx   int
	count4xx   int
	count5xx   int
	routers    map[string]int
	paths      map[string]int
	statuses   map[int]int
	userAgents map[string]int
	lastSeen   time.Time
	errors     []ErrorSample // bounded ring of recent 4xx/5xx
}

// TrafficAnalyzer reads the full Traefik access log to build IP traffic statistics
// over a sliding retention window (default: last 1 hour). Safe for concurrent use.
type TrafficAnalyzer struct {
	path     string
	interval time.Duration

	mu     sync.RWMutex
	counts map[string]*ipCounter
	offset int64
}

// NewTrafficAnalyzer returns an analyzer for the JSON access log at path.
func NewTrafficAnalyzer(path string, interval time.Duration) *TrafficAnalyzer {
	return &TrafficAnalyzer{
		path:     path,
		interval: interval,
		counts:   make(map[string]*ipCounter),
	}
}

// Run starts the polling loop. Blocks until ctx is cancelled.
func (a *TrafficAnalyzer) Run(ctx context.Context) {
	slog.Info("traffic analyzer started", "path", a.path, "interval", a.interval)
	a.poll()
	tk := time.NewTicker(a.interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("traffic analyzer stopped")
			return
		case <-tk.C:
			a.poll()
			a.purgeOld()
		}
	}
}

// TopIPs returns the n most active IPs in the retention window, sorted by total hits.
func (a *TrafficAnalyzer) TopIPs(n int) []IPStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	stats := make([]IPStats, 0, len(a.counts))
	for ip, c := range a.counts {
		stats = append(stats, statsFromCounter(ip, c))
	}
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Total > stats[j].Total
	})
	if len(stats) > n {
		stats = stats[:n]
	}
	return stats
}

// StatsForIP returns the aggregated stats for a single IP, if tracked.
func (a *TrafficAnalyzer) StatsForIP(ip string) (IPStats, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	c, ok := a.counts[ip]
	if !ok {
		return IPStats{}, false
	}
	return statsFromCounter(ip, c), true
}

func statsFromCounter(ip string, c *ipCounter) IPStats {
	er := 0.0
	if c.total > 0 {
		er = float64(c.count4xx+c.count5xx) / float64(c.total)
	}
	topRouter, maxH := "", 0
	for r, h := range c.routers {
		if h > maxH {
			maxH = h
			topRouter = r
		}
	}
	return IPStats{
		IP:            ip,
		Total:         c.total,
		Count2xx:      c.count2xx,
		Count4xx:      c.count4xx,
		Count5xx:      c.count5xx,
		ErrorRate:     er,
		TopRouter:     topRouter,
		TopPaths:      topNStringMap(c.paths, 3),
		TopStatuses:   topNIntMap(c.statuses, 3),
		TopUserAgents: topNStringMap(c.userAgents, 2),
		LastSeen:      c.lastSeen,
	}
}

func topNStringMap(m map[string]int, n int) []KVCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]KVCount, 0, len(m))
	for k, v := range m {
		out = append(out, KVCount{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topNIntMap(m map[int]int, n int) []IntCount {
	if len(m) == 0 {
		return nil
	}
	out := make([]IntCount, 0, len(m))
	for k, v := range m {
		out = append(out, IntCount{Code: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// UniqueIPCount returns the number of distinct IPs tracked in the retention window.
func (a *TrafficAnalyzer) UniqueIPCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.counts)
}

// RecentErrors returns up to n recent 4xx/5xx samples for ip, newest last.
// Returns nil if no error data is available for this IP.
func (a *TrafficAnalyzer) RecentErrors(ip string, n int) ([]ErrorSample, int, int) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	c := a.counts[ip]
	if c == nil {
		return nil, 0, 0
	}
	samples := c.errors
	if len(samples) > n {
		samples = samples[len(samples)-n:]
	}
	out := make([]ErrorSample, len(samples))
	copy(out, samples)
	return out, c.count4xx, c.count5xx
}

func (a *TrafficAnalyzer) poll() {
	f, err := os.Open(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			slog.Debug("traffic analyzer: access log not found — configure Traefik --accesslog.filepath and share the volume", "path", a.path)
		} else {
			slog.Warn("traffic analyzer: open", "err", err)
		}
		return
	}
	defer f.Close()

	info, _ := f.Stat()
	a.mu.Lock()
	if info != nil && info.Size() < a.offset {
		a.offset = 0
	}
	offset := a.offset
	a.mu.Unlock()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return
	}
	raw, _ := io.ReadAll(f)
	if len(raw) == 0 {
		return
	}
	newOffset := offset + int64(len(raw))

	type update struct {
		ip     string
		status int
		method string
		path   string
		router string
		ua     string
		ts     time.Time
	}
	var updates []update

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e analyzerEntry
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		ip := extractIP(e.ClientAddr)
		if ip == "" {
			continue
		}
		ts := parseTime(e.StartUTC, e.Time)
		updates = append(updates, update{ip, e.DownstreamStatus, e.RequestMethod, e.RequestPath, e.RouterName, e.UserAgent, ts})
	}

	a.mu.Lock()
	a.offset = newOffset
	for _, u := range updates {
		c := a.counts[u.ip]
		if c == nil {
			c = &ipCounter{
				routers:    make(map[string]int),
				paths:      make(map[string]int),
				statuses:   make(map[int]int),
				userAgents: make(map[string]int),
			}
			a.counts[u.ip] = c
		}
		c.total++
		switch {
		case u.status >= 200 && u.status < 300:
			c.count2xx++
		case u.status >= 400 && u.status < 500:
			c.count4xx++
		case u.status >= 500:
			c.count5xx++
		}
		if u.router != "" {
			c.routers[u.router]++
		}
		if u.path != "" {
			if _, exists := c.paths[u.path]; exists || len(c.paths) < maxPathsPerIP {
				c.paths[u.path]++
			}
		}
		if u.status > 0 {
			c.statuses[u.status]++
		}
		if u.ua != "" {
			ua := u.ua
			if len(ua) > maxUserAgentLen {
				ua = ua[:maxUserAgentLen]
			}
			if _, exists := c.userAgents[ua]; exists || len(c.userAgents) < maxUserAgentsPerIP {
				c.userAgents[ua]++
			}
		}
		if u.ts.After(c.lastSeen) {
			c.lastSeen = u.ts
		}
		if u.status >= 400 {
			sample := ErrorSample{Status: u.status, Method: u.method, Path: u.path, Time: u.ts}
			c.errors = append(c.errors, sample)
			if len(c.errors) > maxErrorSamplesPerIP {
				c.errors = c.errors[len(c.errors)-maxErrorSamplesPerIP:]
			}
		}
	}
	a.mu.Unlock()
}

func (a *TrafficAnalyzer) purgeOld() {
	cutoff := time.Now().UTC().Add(-retentionPeriod)
	a.mu.Lock()
	defer a.mu.Unlock()
	for ip, c := range a.counts {
		if c.lastSeen.Before(cutoff) {
			delete(a.counts, ip)
		}
	}
	if len(a.counts) > analyzerMaxTrackedIPs {
		type ipAge struct {
			ip   string
			last time.Time
		}
		ages := make([]ipAge, 0, len(a.counts))
		for ip, c := range a.counts {
			ages = append(ages, ipAge{ip, c.lastSeen})
		}
		sort.Slice(ages, func(i, j int) bool { return ages[i].last.Before(ages[j].last) })
		excess := len(a.counts) - analyzerMaxTrackedIPs
		for i := 0; i < excess; i++ {
			delete(a.counts, ages[i].ip)
		}
		slog.Info("traffic analyzer: capped tracked IPs", "evicted", excess, "tracked", len(a.counts))
	}
}
