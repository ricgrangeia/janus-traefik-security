package pulse

import (
	"strconv"
	"strings"
)

const defaultAlertThreshold = 0.10 // 10 % error rate triggers an alert

// ServiceAlert holds aggregated error-rate data for a single Traefik service.
type ServiceAlert struct {
	ServiceName string  `json:"service_name"`
	Total       float64 `json:"total_requests"`
	Count4xx    float64 `json:"count_4xx"`
	Count5xx    float64 `json:"count_5xx"`
	ErrorRate   float64 `json:"error_rate"` // 0.0 – 1.0
}

// Analyze parses the raw Prometheus metrics text returned by Traefik's
// /metrics endpoint and returns services whose combined 4xx+5xx error
// rate exceeds the alert threshold.
func Analyze(metricsText string, threshold float64) []ServiceAlert {
	if threshold <= 0 {
		threshold = defaultAlertThreshold
	}

	// Accumulate per-service counters: total, 4xx sum, 5xx sum.
	type counters struct{ total, c4xx, c5xx float64 }
	agg := map[string]*counters{}

	for _, line := range strings.Split(metricsText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "traefik_service_requests_total{") {
			continue
		}

		svc, code, value, ok := parseRequestsLine(line)
		if !ok {
			continue
		}

		if _, exists := agg[svc]; !exists {
			agg[svc] = &counters{}
		}
		agg[svc].total += value
		switch {
		case code >= 400 && code < 500:
			agg[svc].c4xx += value
		case code >= 500:
			agg[svc].c5xx += value
		}
	}

	var alerts []ServiceAlert
	for svc, c := range agg {
		if c.total == 0 {
			continue
		}
		rate := (c.c4xx + c.c5xx) / c.total
		if rate >= threshold {
			alerts = append(alerts, ServiceAlert{
				ServiceName: svc,
				Total:       c.total,
				Count4xx:    c.c4xx,
				Count5xx:    c.c5xx,
				ErrorRate:   rate,
			})
		}
	}
	return alerts
}

// parseRequestsLine extracts (serviceName, statusCode, value) from a
// Prometheus counter line such as:
//
//	traefik_service_requests_total{code="404",method="GET",protocol="http",service="api@docker"} 17
func parseRequestsLine(line string) (service string, code int, value float64, ok bool) {
	// Split into labels block and value.
	braceEnd := strings.Index(line, "}")
	if braceEnd < 0 {
		return
	}
	labelsStr := line[strings.Index(line, "{")+1 : braceEnd]
	valueStr := strings.TrimSpace(line[braceEnd+1:])

	// The optional Prometheus timestamp follows the value — drop it.
	if sp := strings.IndexByte(valueStr, ' '); sp >= 0 {
		valueStr = valueStr[:sp]
	}

	v, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return
	}

	labels := parseLabels(labelsStr)
	svc, hasSvc := labels["service"]
	codeStr, hasCode := labels["code"]
	if !hasSvc || !hasCode {
		return
	}

	c, err := strconv.Atoi(codeStr)
	if err != nil {
		return
	}

	return svc, c, v, true
}

// parseLabels converts `key="val",key2="val2"` into a map.
func parseLabels(s string) map[string]string {
	result := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		key := pair[:eq]
		val := strings.Trim(pair[eq+1:], `"`)
		result[key] = val
	}
	return result
}
