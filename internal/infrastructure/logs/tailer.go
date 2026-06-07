// Package logs provides near-real-time tailing of Traefik's JSON access log,
// recording 403 responses so Janus can analyse post-ban attacker behaviour.
package logs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

// HitRecord captures one blocked (HTTP 403) access log event.
type HitRecord struct {
	Time   time.Time
	Path   string
	Method string
}

// traefikEntry mirrors the JSON fields Janus reads from Traefik's access log.
// Traefik v2/v3 uses StartUTC (RFC3339Nano); some setups emit "time" instead.
type traefikEntry struct {
	ClientAddr       string `json:"ClientAddr"`
	DownstreamStatus int    `json:"DownstreamStatus"`
	RequestPath      string `json:"RequestPath"`
	RequestMethod    string `json:"RequestMethod"`
	StartUTC         string `json:"StartUTC"`
	Time             string `json:"time"` // fallback field
}

const (
	maxHitsPerIP    = 100            // ring-buffer cap per IP — 100 is enough for the ban-review LLM to reason about post-ban behaviour
	maxTrackedIPs   = 1000           // hard cap on number of IPs in the hits map — protects against unbounded memory growth under bot-scan
	tailerRetention = 2 * time.Hour  // drop IPs whose newest hit is older than this on each poll
	tailerPurgeFreq = 5 * time.Minute // run the purge sweep at most this often
)

// AccessLogTailer reads Traefik's JSON-format access log on a polling interval,
// storing 403 entries per source IP. Safe for concurrent use.
type AccessLogTailer struct {
	path     string
	interval time.Duration

	mu        sync.RWMutex
	hits      map[string][]HitRecord // IP → bounded slice, newest last
	offset    int64
	lastPurge time.Time
}

// NewAccessLogTailer returns a tailer for the JSON access log at path,
// polling every interval for new lines.
func NewAccessLogTailer(path string, interval time.Duration) *AccessLogTailer {
	return &AccessLogTailer{
		path:     path,
		interval: interval,
		hits:     make(map[string][]HitRecord),
	}
}

// Run tails the log until ctx is cancelled. Designed to run in a goroutine.
func (t *AccessLogTailer) Run(ctx context.Context) {
	slog.Info("access-log tailer started", "path", t.path, "interval", t.interval)
	t.poll()
	tk := time.NewTicker(t.interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("access-log tailer stopped")
			return
		case <-tk.C:
			t.poll()
		}
	}
}

// HitsForIP returns all 403 hits for ip recorded since the given time.
func (t *AccessLogTailer) HitsForIP(ip string, since time.Time) []HitRecord {
	t.mu.RLock()
	defer t.mu.RUnlock()
	all := t.hits[ip]
	var out []HitRecord
	for _, h := range all {
		if !h.Time.Before(since) {
			out = append(out, h)
		}
	}
	return out
}

// BucketHits divides the last (buckets × bucketSecs) seconds into equal buckets
// and returns the hit count per bucket, oldest first. Used for sparklines.
func (t *AccessLogTailer) BucketHits(ip string, buckets, bucketSecs int) []int {
	out := make([]int, buckets)
	window := time.Duration(buckets*bucketSecs) * time.Second
	since := time.Now().UTC().Add(-window)
	hits := t.HitsForIP(ip, since)
	now := time.Now().UTC()
	for _, h := range hits {
		age := int(now.Sub(h.Time).Seconds())
		idx := buckets - 1 - age/bucketSecs
		if idx >= 0 && idx < buckets {
			out[idx]++
		}
	}
	return out
}

// poll reads any new log lines appended since the last call.
func (t *AccessLogTailer) poll() {
	f, err := os.Open(t.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("access-log tailer: open", "err", err)
		}
		return
	}
	defer f.Close()

	// Detect log rotation: file smaller than remembered offset → seek to end of new file.
	info, _ := f.Stat()
	t.mu.Lock()
	if info != nil && info.Size() < t.offset {
		slog.Info("access-log tailer: rotation detected, skipping to end of new file", "size", info.Size())
		t.offset = info.Size()
	}
	// Cold start: skip historical log entries to avoid OOM when the existing
	// file is hundreds of MB. Janus only needs new entries from the moment it
	// starts; the ban-review worker uses the last 30 min only.
	if t.offset == 0 && info != nil && info.Size() > 0 {
		slog.Info("access-log tailer: cold start — skipping historical log", "size_bytes", info.Size())
		t.offset = info.Size()
	}
	offset := t.offset
	t.mu.Unlock()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return
	}
	raw, _ := io.ReadAll(f)
	if len(raw) == 0 {
		return
	}
	newOffset := offset + int64(len(raw))

	type pending struct {
		ip  string
		hit HitRecord
	}
	var added []pending

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var e traefikEntry
		if json.Unmarshal(line, &e) != nil {
			continue
		}
		if e.DownstreamStatus != 403 {
			continue
		}
		ip := extractIP(e.ClientAddr)
		if ip == "" {
			continue
		}
		ts := parseTime(e.StartUTC, e.Time)
		added = append(added, pending{ip, HitRecord{Time: ts, Path: e.RequestPath, Method: e.RequestMethod}})
	}

	t.mu.Lock()
	t.offset = newOffset
	for _, a := range added {
		rec := append(t.hits[a.ip], a.hit)
		if len(rec) > maxHitsPerIP {
			rec = rec[len(rec)-maxHitsPerIP:]
		}
		t.hits[a.ip] = rec
	}
	if time.Since(t.lastPurge) >= tailerPurgeFreq {
		t.purgeLocked()
		t.lastPurge = time.Now()
	}
	t.mu.Unlock()
}

// purgeLocked is the memory guard for the hits map. Caller must hold t.mu.
// 1. Drop any IP whose most recent hit is older than tailerRetention.
// 2. If still above maxTrackedIPs, evict the oldest-last-hit entries until
//    under cap. This prevents unbounded memory growth during sustained
//    bot-scan traffic (the original cause of the 6.9 GB RES incident).
func (t *AccessLogTailer) purgeLocked() {
	if len(t.hits) == 0 {
		return
	}
	cutoff := time.Now().UTC().Add(-tailerRetention)
	dropped := 0
	for ip, recs := range t.hits {
		if len(recs) == 0 || recs[len(recs)-1].Time.Before(cutoff) {
			delete(t.hits, ip)
			dropped++
		}
	}
	if len(t.hits) > maxTrackedIPs {
		// LRU eviction by newest-hit time.
		type ipAge struct {
			ip   string
			last time.Time
		}
		ages := make([]ipAge, 0, len(t.hits))
		for ip, recs := range t.hits {
			last := time.Time{}
			if len(recs) > 0 {
				last = recs[len(recs)-1].Time
			}
			ages = append(ages, ipAge{ip, last})
		}
		sort.Slice(ages, func(i, j int) bool { return ages[i].last.Before(ages[j].last) })
		excess := len(t.hits) - maxTrackedIPs
		for i := 0; i < excess; i++ {
			delete(t.hits, ages[i].ip)
		}
		dropped += excess
	}
	if dropped > 0 {
		slog.Info("access-log tailer: purged stale IPs", "dropped", dropped, "tracked", len(t.hits))
	}
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // already a plain IP (no port)
	}
	return host
}

func parseTime(candidates ...string) time.Time {
	for _, s := range candidates {
		if s == "" {
			continue
		}
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC()
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}
