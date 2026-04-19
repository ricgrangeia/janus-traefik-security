package traefik

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Client talks to Traefik's internal REST API.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// RawData mirrors Traefik's /api/rawdata response.
type RawData struct {
	Routers     map[string]Router     `json:"routers"`
	Services    map[string]Service    `json:"services"`
	Middlewares map[string]Middleware `json:"middlewares"`
}

type Router struct {
	EntryPoints []string `json:"entryPoints"`
	Middlewares []string `json:"middlewares"`
	Service     string   `json:"service"`
	Rule        string   `json:"rule"`
	TLS         *TLS     `json:"tls"`
	Status      string   `json:"status"`
	Provider    string   `json:"provider"`
}

type TLS struct {
	CertResolver string `json:"certResolver"`
}

type Service struct {
	Status       string            `json:"status"`
	ServerStatus map[string]string `json:"serverStatus"`
	Provider     string            `json:"provider"`
}

// Middleware — type field is set by Traefik (e.g. "basicauth", "forwardauth").
type Middleware struct {
	Type     string `json:"type"`
	Status   string `json:"status"`
	Provider string `json:"provider"`
}

// Overview mirrors Traefik's /api/overview response.
type Overview struct {
	HTTP struct {
		Routers     EntitiesStats `json:"routers"`
		Services    EntitiesStats `json:"services"`
		Middlewares EntitiesStats `json:"middlewares"`
	} `json:"http"`
	Features struct {
		AccessLog bool   `json:"accessLog"`
		Metrics   string `json:"metrics"`
	} `json:"features"`
	Providers []string `json:"providers"`
}

type EntitiesStats struct {
	Total    int `json:"total"`
	Warnings int `json:"warnings"`
	Errors   int `json:"errors"`
	Enabled  int `json:"enabled"`
}

func (c *Client) FetchRawData() (*RawData, error) {
	return fetchJSON[RawData](c, "/api/rawdata")
}

func (c *Client) FetchOverview() (*Overview, error) {
	return fetchJSON[Overview](c, "/api/overview")
}

// FetchMetrics returns the raw Prometheus metrics text from Traefik.
func (c *Client) FetchMetrics() (string, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/metrics")
	if err != nil {
		return "", fmt.Errorf("metrics request failed: %w", err)
	}
	defer resp.Body.Close()

	var sb strings.Builder
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String(), nil
}

// Ping returns true if the Traefik API is reachable.
// Uses /api/overview rather than /ping because --ping is not enabled by default
// in most Traefik deployments; the API endpoint is always present when --api is on.
func (c *Client) Ping() bool {
	resp, err := c.httpClient.Get(c.baseURL + "/api/overview")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func fetchJSON[T any](c *Client, path string) (*T, error) {
	resp, err := c.httpClient.Get(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("traefik returned %d for %s", resp.StatusCode, path)
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &result, nil
}
