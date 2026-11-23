package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
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
	mu                        sync.Mutex
	sessions                  map[string]pendingChallenge
	credentialIDsByUserHandle map[string][]string
}

type registrationOptions struct {
	RP                     relyingParty           `json:"rp"`
	User                   registrationUser       `json:"user"`
	Challenge              string                 `json:"challenge"`
	PubKeyCredParams       []credentialParameter  `json:"pubKeyCredParams"`
	AuthenticatorSelection authenticatorSelection `json:"authenticatorSelection"`
	ExcludeCredentials     []credentialDescriptor `json:"excludeCredentials"`
	Attestation            string                 `json:"attestation"`
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

type authenticatorSelection struct {
	ResidentKey      string `json:"residentKey"`
	UserVerification string `json:"userVerification"`
}

type credentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
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
		AuthenticatorSelection: authenticatorSelection{
			ResidentKey:      "required",
			UserVerification: "required",
		},
		ExcludeCredentials: s.excludedCredentials(demoUserHandle),
		Attestation:        "none",
	})
}

func (s *sessionStore) excludedCredentials(userHandle string) []credentialDescriptor {
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := s.credentialIDsByUserHandle[userHandle]
	credentials := make([]credentialDescriptor, 0, len(ids))
	for _, id := range ids {
		credentials = append(credentials, credentialDescriptor{Type: "public-key", ID: id})
	}
	return credentials
}

func (s *sessionStore) handleRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	pending, ok := s.consumeChallenge(r, registerOperation)
	if !ok {
		http.Error(w, "no valid registration challenge", http.StatusBadRequest)
		return
	}

	const maxRegistrationBody = 64 << 10
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRegistrationBody))
	if err != nil {
		http.Error(w, "could not read registration response", http.StatusBadRequest)
		return
	}
	var credential struct {
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &credential); err != nil {
		http.Error(w, "invalid registration response JSON", http.StatusBadRequest)
		return
	}

	rawClientData, err := base64.RawURLEncoding.Strict().DecodeString(credential.Response.ClientDataJSON)
	if err != nil {
		http.Error(w, "invalid clientDataJSON encoding", http.StatusBadRequest)
		return
	}
	var clientData struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
		TopOrigin   string `json:"topOrigin"`
	}
	if err := json.Unmarshal(rawClientData, &clientData); err != nil {
		http.Error(w, "invalid clientDataJSON", http.StatusBadRequest)
		return
	}
	if clientData.Type != "webauthn.create" || clientData.Challenge != pending.value ||
		clientData.Origin != rpOrigin || clientData.CrossOrigin ||
		(clientData.TopOrigin != "" && clientData.TopOrigin != rpOrigin) {
		http.Error(w, "unexpected registration client data", http.StatusBadRequest)
		return
	}

	authData, err := parseNoneAttestation(credential.Response.AttestationObject)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := verifyRegistrationAuthenticatorData(authData); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// credential ID と公開鍵の検証・保存は後続の項目で追加する。
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
