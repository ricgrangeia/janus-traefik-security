// Package netinfo discovers the public IP address Janus is reachable from —
// used to self-heal admin access after a dynamic ISP IP changes.
package netinfo

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// providers are queried in order; the first one that returns a valid IP wins.
// Plain-text endpoints only — no JSON parsing needed.
var providers = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
}

// DiscoverPublicIP asks a short list of external echo services for the
// caller's public IP address, trying each in turn until one answers within
// timeout. Returns an error only if every provider fails.
func DiscoverPublicIP(ctx context.Context, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}

	var lastErr error
	for _, url := range providers {
		ip, err := fetchIP(ctx, client, url)
		if err != nil {
			lastErr = err
			continue
		}
		return ip, nil
	}
	return "", fmt.Errorf("all public-IP providers failed: %w", lastErr)
}

func fetchIP(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: unexpected status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("%s: not a valid IP: %q", url, ip)
	}
	return ip, nil
}
