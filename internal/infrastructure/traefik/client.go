package traefik

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/janus-project/janus/domain"
)

// Client is the HTTP adapter for Traefik's internal REST API.
// It speaks only in DTOs — translation to domain types is the Mapper's job.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a Client pointed at the given Traefik API base URL.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Ping returns true when Traefik's API is reachable.
// Uses /api/overview rather than /ping because --ping is not enabled by default.
func (c *Client) Ping() bool {
	resp, err := c.httpClient.Get(c.baseURL + "/api/overview")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// FetchRawData fetches and decodes /api/rawdata.
// Returns a domain.InfrastructureError wrapping domain.ErrTraefikUnreachable
// or domain.ErrTraefikBadData so callers can use errors.Is without importing
// HTTP or JSON packages.
func (c *Client) FetchRawData() (*RawDataDTO, error) {
	dto, err := fetchDTO[RawDataDTO](c, "/api/rawdata")
	if err != nil {
		return nil, err
	}
	return dto, nil
}

// FetchOverview fetches and decodes /api/overview.
func (c *Client) FetchOverview() (*OverviewDTO, error) {
	return fetchDTO[OverviewDTO](c, "/api/overview")
}

// FetchMetrics returns the raw Prometheus text from /metrics.
func (c *Client) FetchMetrics() (string, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/metrics")
	if err != nil {
		return "", domain.InfrastructureError{
			Sentinel: domain.ErrTraefikUnreachable,
			Cause:    fmt.Errorf("GET /metrics: %w", err),
		}
	}
	defer resp.Body.Close()

	var sb strings.Builder
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if readErr != nil {
			break
		}
	}
	return sb.String(), nil
}

// fetchDTO is a generic helper that GETs a Traefik API endpoint and decodes JSON.
func fetchDTO[T any](c *Client, path string) (*T, error) {
	resp, err := c.httpClient.Get(c.baseURL + path)
	if err != nil {
		return nil, domain.InfrastructureError{
			Sentinel: domain.ErrTraefikUnreachable,
			Cause:    fmt.Errorf("GET %s: %w", path, err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, domain.InfrastructureError{
			Sentinel: domain.ErrTraefikBadData,
			Cause:    fmt.Errorf("GET %s returned HTTP %d", path, resp.StatusCode),
		}
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, domain.InfrastructureError{
			Sentinel: domain.ErrTraefikBadData,
			Cause:    fmt.Errorf("decode %s: %w", path, err),
		}
	}
	return &result, nil
}
