package pulse

import "testing"

func TestAnalyze_AboveThreshold(t *testing.T) {
	text := `
# HELP traefik_service_requests_total
traefik_service_requests_total{service="api@docker",code="200",method="GET",protocol="http"} 80
traefik_service_requests_total{service="api@docker",code="404",method="GET",protocol="http"} 15
traefik_service_requests_total{service="api@docker",code="500",method="GET",protocol="http"} 5
`
	alerts := Analyze(text, 0.10)
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert, got %d", len(alerts))
	}
	a := alerts[0]
	if a.ServiceName != "api@docker" {
		t.Errorf("service: got %q", a.ServiceName)
	}
	if a.Total != 100 || a.Count4xx != 15 || a.Count5xx != 5 {
		t.Errorf("counts: total=%v 4xx=%v 5xx=%v", a.Total, a.Count4xx, a.Count5xx)
	}
	if a.ErrorRate != 0.20 {
		t.Errorf("rate: got %v", a.ErrorRate)
	}
}

func TestAnalyze_BelowThreshold(t *testing.T) {
	text := `traefik_service_requests_total{service="api@docker",code="200"} 95
traefik_service_requests_total{service="api@docker",code="500"} 5
`
	alerts := Analyze(text, 0.10)
	if len(alerts) != 0 {
		t.Fatalf("want 0 alerts, got %d", len(alerts))
	}
}

func TestAnalyze_IgnoresCommentsAndOtherMetrics(t *testing.T) {
	text := `# HELP something
traefik_entrypoint_requests_total{entrypoint="web",code="500"} 999
traefik_service_requests_total{service="x@docker",code="500"} 10
traefik_service_requests_total{service="x@docker",code="200"} 10
`
	alerts := Analyze(text, 0.10)
	if len(alerts) != 1 || alerts[0].ServiceName != "x@docker" {
		t.Fatalf("unexpected alerts: %+v", alerts)
	}
}

func TestAnalyze_DefaultsZeroThresholdTo10Percent(t *testing.T) {
	text := `traefik_service_requests_total{service="s@docker",code="200"} 91
traefik_service_requests_total{service="s@docker",code="404"} 9
`
	if got := Analyze(text, 0); len(got) != 0 {
		t.Fatalf("expected no alert at 9%% with default 10%% threshold, got %d", len(got))
	}
}

func TestParseRequestsLine(t *testing.T) {
	svc, code, val, ok := parseRequestsLine(`traefik_service_requests_total{service="x@docker",code="404"} 42`)
	if !ok || svc != "x@docker" || code != 404 || val != 42 {
		t.Fatalf("parse: svc=%q code=%d val=%v ok=%v", svc, code, val, ok)
	}
}
