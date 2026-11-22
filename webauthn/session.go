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
	registerOperation = "register"
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
	challenge := s.issueChallenge(w, r, registerOperation, demoUserHandle)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(struct {
		Challenge string `json:"challenge"`
	}{Challenge: challenge})
}

func (s *sessionStore) handleRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.consumeChallenge(r, registerOperation); !ok {
		http.Error(w, "no valid registration challenge", http.StatusBadRequest)
		return
	}
	// 登録レスポンスの検証は Step 3 で追加する。
	w.WriteHeader(http.StatusNoContent)
}

func (s *sessionStore) consumeChallenge(r *http.Request, operation string) (pendingChallenge, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return pendingChallenge{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pending, ok := s.sessions[cookie.Value]
	if !ok {
		return pendingChallenge{}, false
	}
	if !time.Now().Before(pending.expiresAt) {
		delete(s.sessions, cookie.Value)
		return pendingChallenge{}, false
	}
	if pending.operation != operation {
		return pendingChallenge{}, false
	}
	delete(s.sessions, cookie.Value)
	return pending, true
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
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
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
