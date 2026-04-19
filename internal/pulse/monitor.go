package pulse

import (
	"strconv"
	"strings"

	"github.com/janus-project/janus/domain"
)

const defaultAlertThreshold = 0.10 // 10 % error rate triggers an alert

// Analyze parses the raw Prometheus metrics text returned by Traefik's
// /metrics endpoint and returns domain.PulseAlerts for services whose
// combined 4xx+5xx error rate exceeds the alert threshold.
func Analyze(metricsText string, threshold float64) []domain.PulseAlert {
	if threshold <= 0 {
		threshold = defaultAlertThreshold
	}

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

	var alerts []domain.PulseAlert
	for svc, c := range agg {
		if c.total == 0 {
			continue
		}
		rate := (c.c4xx + c.c5xx) / c.total
		if rate >= threshold {
			alerts = append(alerts, domain.PulseAlert{
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

func parseRequestsLine(line string) (service string, code int, value float64, ok bool) {
	braceEnd := strings.Index(line, "}")
	if braceEnd < 0 {
		return
	}
	labelsStr := line[strings.Index(line, "{")+1 : braceEnd]
	valueStr := strings.TrimSpace(line[braceEnd+1:])

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

func parseLabels(s string) map[string]string {
	result := map[string]string{}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		result[pair[:eq]] = strings.Trim(pair[eq+1:], `"`)
	}
	return result
}
