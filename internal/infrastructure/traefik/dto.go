// Package traefik contains the infrastructure adapter for Traefik's REST API.
// It owns three concerns: DTOs (this file), the HTTP Client, and the ACL Mapper.
// Nothing in this package is imported by the domain layer.
package traefik

// ── API response DTOs ─────────────────────────────────────────────────────
// Field names and JSON tags mirror Traefik's actual API response exactly.
// These structs must never be used outside the infrastructure layer.

// RawDataDTO mirrors Traefik's /api/rawdata response.
type RawDataDTO struct {
	Routers     map[string]RouterDTO     `json:"routers"`
	Services    map[string]ServiceDTO    `json:"services"`
	Middlewares map[string]MiddlewareDTO `json:"middlewares"`
}

// RouterDTO represents a single Traefik router as returned by the API.
type RouterDTO struct {
	EntryPoints []string   `json:"entryPoints"`
	Middlewares []string   `json:"middlewares"`
	Service     string     `json:"service"`
	Rule        string     `json:"rule"`
	TLS         *TLSDTO    `json:"tls"`
	Status      string     `json:"status"`
	Provider    string     `json:"provider"`
}

// TLSDTO holds TLS configuration for a router.
type TLSDTO struct {
	CertResolver string `json:"certResolver"`
}

// ServiceDTO represents a Traefik backend service.
type ServiceDTO struct {
	Status       string            `json:"status"`
	ServerStatus map[string]string `json:"serverStatus"`
	Provider     string            `json:"provider"`
}

// MiddlewareDTO represents a Traefik middleware instance.
// The Type field is set by Traefik (e.g. "basicauth", "ratelimit").
type MiddlewareDTO struct {
	Type     string `json:"type"`
	Status   string `json:"status"`
	Provider string `json:"provider"`
}

// OverviewDTO mirrors Traefik's /api/overview response.
type OverviewDTO struct {
	HTTP struct {
		Routers     EntitiesStatsDTO `json:"routers"`
		Services    EntitiesStatsDTO `json:"services"`
		Middlewares EntitiesStatsDTO `json:"middlewares"`
	} `json:"http"`
	Features struct {
		AccessLog bool   `json:"accessLog"`
		Metrics   string `json:"metrics"`
	} `json:"features"`
	Providers []string `json:"providers"`
}

// EntitiesStatsDTO holds aggregate counts for a class of Traefik entities.
type EntitiesStatsDTO struct {
	Total    int `json:"total"`
	Warnings int `json:"warnings"`
	Errors   int `json:"errors"`
	Enabled  int `json:"enabled"`
}
