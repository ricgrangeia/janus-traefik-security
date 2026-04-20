package auth

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	CookieName     = "janus_session"
	loginWindow    = 15 * time.Minute
	loginMaxTries  = 5
	defaultSessTTL = 8 * time.Hour
)

// Guard enforces authentication on protected routes.
type Guard struct {
	passwordHash string
	apiToken     string
	sessions     *SessionStore
	attempts     *attemptTracker
}

// NewGuard constructs a Guard. If passwordHash is empty, authentication is DISABLED
// and all requests pass through (logged once at startup by the caller).
func NewGuard(passwordHash, apiToken string) *Guard {
	return &Guard{
		passwordHash: strings.TrimSpace(passwordHash),
		apiToken:     strings.TrimSpace(apiToken),
		sessions:     NewSessionStore(defaultSessTTL),
		attempts:     newAttemptTracker(),
	}
}

// Enabled reports whether authentication is active.
func (g *Guard) Enabled() bool { return g.passwordHash != "" }

// Middleware wraps a handler, requiring a valid session cookie or bearer token.
// Unauthenticated HTML-ish requests are redirected to /login.html; API requests get 401.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.Enabled() || g.isAuthenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		http.Redirect(w, r, "/login.html", http.StatusFound)
	})
}

func (g *Guard) isAuthenticated(r *http.Request) bool {
	if g.apiToken != "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			tok := strings.TrimPrefix(h, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(tok), []byte(g.apiToken)) == 1 {
				return true
			}
		}
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	return g.sessions.Validate(c.Value)
}

// HandleLogin validates the submitted password and issues a session cookie.
// POST body: {"password":"..."}
func (g *Guard) HandleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !g.attempts.allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "too many failed attempts — try again later",
		})
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password required"})
		return
	}

	if !g.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "authentication is not configured on this instance",
		})
		return
	}

	if !VerifyPassword(body.Password, g.passwordHash) {
		g.attempts.fail(ip)
		slog.Warn("login failed", "ip", ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	g.attempts.reset(ip)
	id, err := g.sessions.Create()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not create session"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsTLS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(defaultSessTTL.Seconds()),
	})
	slog.Info("login ok", "ip", ip)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// HandleLogout revokes the current session and clears the cookie.
func (g *Guard) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		g.sessions.Revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsTLS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// HandleStatus lets the SPA check whether the current request is authenticated.
func (g *Guard) HandleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":       g.Enabled(),
		"authenticated": !g.Enabled() || g.isAuthenticated(r),
	})
}

// ── helpers ─────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func requestIsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// ── login-attempt throttle ──────────────────────────────────────────────

type attemptTracker struct {
	mu      sync.Mutex
	entries map[string]*attemptEntry
}

type attemptEntry struct {
	count     int
	firstSeen time.Time
}

func newAttemptTracker() *attemptTracker {
	return &attemptTracker{entries: make(map[string]*attemptEntry)}
}

func (t *attemptTracker) allow(ip string) bool {
	if ip == "" {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[ip]
	if !ok {
		return true
	}
	if time.Since(e.firstSeen) > loginWindow {
		delete(t.entries, ip)
		return true
	}
	return e.count < loginMaxTries
}

func (t *attemptTracker) fail(ip string) {
	if ip == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[ip]
	if !ok || time.Since(e.firstSeen) > loginWindow {
		t.entries[ip] = &attemptEntry{count: 1, firstSeen: time.Now()}
		return
	}
	e.count++
}

func (t *attemptTracker) reset(ip string) {
	t.mu.Lock()
	delete(t.entries, ip)
	t.mu.Unlock()
}
