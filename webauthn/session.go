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
	rpID              = "localhost"
	es256Algorithm    = -7
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

type registrationOptions struct {
	RP               relyingParty          `json:"rp"`
	User             registrationUser      `json:"user"`
	Challenge        string                `json:"challenge"`
	PubKeyCredParams []credentialParameter `json:"pubKeyCredParams"`
}

type relyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type registrationUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type credentialParameter struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

func (s *sessionStore) handleRegistrationOptions(w http.ResponseWriter, r *http.Request) {
	challenge := s.issueChallenge(w, r, registerOperation, demoUserHandle)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(registrationOptions{
		RP:        relyingParty{ID: rpID, Name: "study-Auth"},
		User:      registrationUser{ID: demoUserHandle, Name: demoUsername, DisplayName: demoUsername},
		Challenge: challenge,
		PubKeyCredParams: []credentialParameter{
			{Type: "public-key", Alg: es256Algorithm},
		},
	})
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
