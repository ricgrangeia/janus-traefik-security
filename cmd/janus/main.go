package main

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/janus-project/janus/internal/app"
	"github.com/janus-project/janus/internal/infrastructure/firewall"
	"github.com/janus-project/janus/internal/infrastructure/geoip"
	"github.com/janus-project/janus/internal/infrastructure/llm"
	janusLogs "github.com/janus-project/janus/internal/infrastructure/logs"
	"github.com/janus-project/janus/internal/infrastructure/storage"
	"github.com/janus-project/janus/internal/infrastructure/telegram"
	traefikinfra "github.com/janus-project/janus/internal/infrastructure/traefik"
	"github.com/janus-project/janus/internal/security"
	janusWeb "github.com/janus-project/janus/internal/web"
	"github.com/janus-project/janus/internal/web/api"
)

// config holds all runtime configuration sourced from environment variables.
type config struct {
	TraefikURL        string
	Port              string
	AlertThreshold    float64
	VLLMEnabled       bool
	VLLMURL           string
	VLLMModel         string
	VLLMAPIKey        string
	AIAuditInterval   time.Duration
	JanusEnv          string
	KnownMiddlewares  string
	AITracePath       string
	HistoryPath       string
	TelegramToken     string
	TelegramChatID    string
	ThreatSeverityMin int
	PoliciesPath      string
	DBPath            string
	ShieldPath        string
	ShieldStatePath   string
	JanusInternalURL  string
	AutoBlockMin      int
	AccessLogPath     string
	GeoIPPath         string
	WhitelistPath     string
}

func main() {
	cfg := loadConfig()

	slog.Info("Janus starting",
		"port", cfg.Port,
		"traefik_url", cfg.TraefikURL,
		"ai_enabled", cfg.VLLMEnabled,
		"env", cfg.JanusEnv,
		"telegram_enabled", cfg.TelegramToken != "",
	)

	client := traefikinfra.NewClient(cfg.TraefikURL)
	auditor := security.NewAuditor()

	policies, err := app.LoadPolicies(cfg.PoliciesPath)
	if err != nil {
		log.Fatalf("load policies: %v", err)
	}

	// ── History / persistence (SQLite preferred, JSON fallback) ─────────────
	var historyRepo storage.Store
	var richRepo storage.RichStore
	if cfg.DBPath != "" {
		r, err := storage.NewSQLiteRepository(cfg.DBPath)
		if err != nil {
			log.Fatalf("open SQLite database: %v", err)
		}
		historyRepo = r
		richRepo = r
	} else if cfg.HistoryPath != "" {
		historyRepo = storage.NewRepository(cfg.HistoryPath)
	}

	// ── Trusted-IP whitelist (shield immunity source) ─────────────────────
	whitelist := app.NewWhitelistService(cfg.WhitelistPath)

	// ── Shield ────────────────────────────────────────────────────────────
	shield := firewall.NewShieldService(cfg.ShieldPath, cfg.ShieldStatePath, cfg.JanusInternalURL).
		WithImmunity(whitelist.Contains)

	// ── Optional AI worker + consult service ─────────────────────────────
	var (
		aiWorker   *app.AIAuditWorker
		consultSvc *app.ConsultService
		llmClient  *llm.Client
	)
	if cfg.VLLMEnabled {
		known := app.ParseKnownMiddlewares(cfg.KnownMiddlewares)
		llmClient = llm.NewClient(cfg.VLLMURL, cfg.VLLMModel, cfg.VLLMAPIKey)
		analyst := llm.NewAnalyst(llmClient, cfg.JanusEnv, known).
			WithProtectedIPs(whitelist.List)
		aiWorker = app.NewAIAuditWorker(
			client, auditor, analyst,
			cfg.AlertThreshold, cfg.AIAuditInterval, cfg.AITracePath,
		)
		if historyRepo != nil {
			aiWorker.WithStorage(historyRepo)
			consultSvc = app.NewConsultService(llmClient, historyRepo)
		}
		if cfg.TelegramToken != "" {
			notifier := telegram.NewNotifier(cfg.TelegramToken, cfg.TelegramChatID)
			aiWorker.WithNotifier(notifier, cfg.ThreatSeverityMin)
		}
		aiWorker.WithShield(shield, cfg.AutoBlockMin)
	}

	// ── GeoIP ────────────────────────────────────────────────────────────
	geoReader, err := geoip.NewReader(cfg.GeoIPPath)
	if err != nil {
		slog.Warn("GeoIP database unavailable", "path", cfg.GeoIPPath, "err", err)
		geoReader, _ = geoip.NewReader("")
	}
	defer geoReader.Close()

	// ── Access log ───────────────────────────────────────────────────────
	var (
		logTailer       *janusLogs.AccessLogTailer
		trafficAnalyzer *janusLogs.TrafficAnalyzer
	)
	if cfg.AccessLogPath != "" {
		logTailer = janusLogs.NewAccessLogTailer(cfg.AccessLogPath, 5*time.Second)
		trafficAnalyzer = janusLogs.NewTrafficAnalyzer(cfg.AccessLogPath, 60*time.Second)
	}

	// ── Ban review worker (requires AI + tailer) ─────────────────────────
	var reviewWorker *app.BanReviewWorker
	if llmClient != nil && logTailer != nil {
		reviewWorker = app.NewBanReviewWorker(shield, logTailer, llmClient, 30*time.Minute)
	}

	// ── Threat intelligence ──────────────────────────────────────────────
	var intelSvc *app.ThreatIntelService
	if llmClient != nil && trafficAnalyzer != nil {
		intelSvc = app.NewThreatIntelService(trafficAnalyzer, geoReader, llmClient).
			WithWhitelist(whitelist)
	}

	// ── HTTP server ───────────────────────────────────────────────────────
	sub, err := fs.Sub(janusWeb.StaticFS, "static")
	if err != nil {
		log.Fatalf("embed sub-FS: %v", err)
	}

	srvAPI := &api.Server{
		Client:          client,
		Auditor:         auditor,
		Shield:          shield,
		Whitelist:       whitelist,
		AIWorker:        aiWorker,
		ReviewWorker:    reviewWorker,
		ConsultSvc:      consultSvc,
		IntelSvc:        intelSvc,
		LogTailer:       logTailer,
		TrafficAnalyzer: trafficAnalyzer,
		HistoryRepo:     historyRepo,
		RichRepo:        richRepo,
		Policies:        policies,
		StaticFS:        sub,
		AlertThreshold:  cfg.AlertThreshold,
		AIEnabled:       cfg.VLLMEnabled,
	}

	// ── Root context bound to SIGINT/SIGTERM ──────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	startWorker := func(name string, run func(context.Context)) {
		if run == nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			run(ctx)
			slog.Info("worker stopped", "name", name)
		}()
	}

	if aiWorker != nil {
		startWorker("ai-audit", aiWorker.Run)
	}
	if logTailer != nil {
		startWorker("log-tailer", logTailer.Run)
	}
	if trafficAnalyzer != nil {
		startWorker("traffic-analyzer", trafficAnalyzer.Run)
	}
	if reviewWorker != nil {
		startWorker("ban-review", reviewWorker.Run)
	}

	addr := ":" + cfg.Port
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srvAPI.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("Janus ready", "addr", addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
		close(serverErr)
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case err := <-serverErr:
		if err != nil {
			log.Fatalf("server: %v", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		slog.Warn("HTTP server shutdown", "err", err)
	}

	wg.Wait()
	slog.Info("Janus stopped cleanly")
}

// ── Config ────────────────────────────────────────────────────────────────

func loadConfig() config {
	cfg := config{
		TraefikURL:        getEnv("TRAEFIK_API_URL", "http://traefik:8080"),
		Port:              getEnv("JANUS_PORT", "9090"),
		AlertThreshold:    0.10,
		VLLMURL:           getEnv("VLLM_API_URL", ""),
		VLLMModel:         getEnv("VLLM_MODEL", "qwen2.5-7b-instruct"),
		VLLMAPIKey:        getEnv("VLLM_API_KEY", ""),
		AIAuditInterval:   60 * time.Second,
		JanusEnv:          getEnv("JANUS_ENV", "production"),
		KnownMiddlewares:  getEnv("JANUS_KNOWN_MIDDLEWARES", ""),
		AITracePath:       getEnv("JANUS_AI_TRACE_PATH", "/logs/ai_audit_trace.json"),
		HistoryPath:       getEnv("JANUS_HISTORY_PATH", "/logs/audit_history.json"),
		TelegramToken:     getEnv("TELEGRAM_BOT_TOKEN", ""),
		TelegramChatID:    getEnv("TELEGRAM_CHAT_ID", ""),
		ThreatSeverityMin: 8,
		AutoBlockMin:      10,
		PoliciesPath:      getEnv("JANUS_POLICIES_PATH", "/configs/policies.json"),
		DBPath:            getEnv("JANUS_DB_PATH", "/app/data/janus.db"),
		ShieldPath:        getEnv("JANUS_SHIELD_PATH", "/rules/janus-middleware.yaml"),
		ShieldStatePath:   getEnv("JANUS_SHIELD_STATE_PATH", "/app/data/shield_state.json"),
		JanusInternalURL:  getEnv("JANUS_INTERNAL_URL", "http://janus:9090"),
		AccessLogPath:     getEnv("JANUS_ACCESS_LOG_PATH", "/logs/access.log"),
		GeoIPPath:         getEnv("JANUS_GEOIP_DB_PATH", "/app/data/GeoLite2-City.mmdb"),
		WhitelistPath:     getEnv("JANUS_WHITELIST_PATH", "/app/data/whitelist.json"),
	}
	if v := os.Getenv("JANUS_AUTO_BLOCK_MIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10 {
			cfg.AutoBlockMin = n
		}
	}
	if v := os.Getenv("JANUS_ALERT_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f <= 1 {
			cfg.AlertThreshold = f
		}
	}
	if v := os.Getenv("JANUS_AI_INTERVAL"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 10 {
			cfg.AIAuditInterval = time.Duration(secs) * time.Second
		}
	}
	if v := os.Getenv("TELEGRAM_SEVERITY_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= 10 {
			cfg.ThreatSeverityMin = n
		}
	}
	cfg.VLLMEnabled = cfg.VLLMURL != ""
	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
