package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// SessionStore holds active session IDs in memory. Restart invalidates all sessions —
// acceptable for a single-instance sidecar.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
	ttl      time.Duration
}

func NewSessionStore(ttl time.Duration) *SessionStore {
	return &SessionStore{sessions: make(map[string]time.Time), ttl: ttl}
}

// Create returns a new 32-byte random session ID and records its expiry.
func (s *SessionStore) Create() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.sessions[id] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	return id, nil
}

// Validate reports whether the session is still live and extends its expiry (sliding TTL).
func (s *SessionStore) Validate(id string) bool {
	if id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.sessions[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.sessions, id)
		return false
	}
	s.sessions[id] = time.Now().Add(s.ttl)
	return true
}

// Revoke removes a session — used by logout.
func (s *SessionStore) Revoke(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// Sweep drops expired sessions. Call periodically from a worker, or leave it —
// Validate also clears expired entries lazily.
func (s *SessionStore) Sweep() {
	now := time.Now()
	s.mu.Lock()
	for id, exp := range s.sessions {
		if now.After(exp) {
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()
}
