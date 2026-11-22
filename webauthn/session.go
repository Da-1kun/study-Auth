package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookieName = "webauthn_sid"
	challengeLifetime = 5 * time.Minute
)

type pendingChallenge struct {
	value      string
	operation  string
	userHandle string
	expiresAt  time.Time
}

// sessionStore はセッション ID ごとに進行中の challenge を保持する。
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]pendingChallenge
}

func (s *sessionStore) handleRegistrationOptions(w http.ResponseWriter, r *http.Request) {
	challenge := s.issueChallenge(w, r, "register", demoUserHandle)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(struct {
		Challenge string `json:"challenge"`
	}{Challenge: challenge})
}

func (s *sessionStore) issueChallenge(w http.ResponseWriter, r *http.Request, operation, userHandle string) string {
	value := randomToken()
	now := time.Now()
	pending := pendingChallenge{
		value:      value,
		operation:  operation,
		userHandle: userHandle,
		expiresAt:  now.Add(challengeLifetime),
	}

	cookie, _ := r.Cookie(sessionCookieName)
	s.mu.Lock()
	for id, session := range s.sessions {
		if !now.Before(session.expiresAt) {
			delete(s.sessions, id)
		}
	}
	if cookie != nil {
		if _, ok := s.sessions[cookie.Value]; ok {
			s.sessions[cookie.Value] = pending
			s.mu.Unlock()
			return value
		}
	}
	id := randomToken()
	s.sessions[id] = pending
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookieName,
		Value: id,
		Path:  "/",
	})
	return value
}

func randomToken() string {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
