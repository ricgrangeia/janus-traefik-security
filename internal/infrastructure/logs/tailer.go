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

const maxHitsPerIP = 1000 // ring-buffer cap per IP

// AccessLogTailer reads Traefik's JSON-format access log on a polling interval,
// storing 403 entries per source IP. Safe for concurrent use.
type AccessLogTailer struct {
	path     string
	interval time.Duration

	mu     sync.RWMutex
	hits   map[string][]HitRecord // IP → bounded slice, newest last
	offset int64
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

	// Detect log rotation: file smaller than remembered offset → reset.
	info, _ := f.Stat()
	t.mu.Lock()
	if info != nil && info.Size() < t.offset {
		slog.Info("access-log tailer: rotation detected, resetting")
		t.offset = 0
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
	t.mu.Unlock()
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
