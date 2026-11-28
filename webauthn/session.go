package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"
)

const (
	sessionCookieName = "webauthn_sid"
	challengeLifetime = 5 * time.Minute
	registerOperation = "register"
	loginOperation    = "login"
	rpID              = "localhost"
	es256Algorithm    = -7
	maxCredentialBody = 64 << 10
)

type pendingChallenge struct {
	value            string
	operation        string
	userHandle       string
	expiresAt        time.Time
	allowCredentials []credentialDescriptor
}

type registeredCredential struct {
	userHandle     string
	publicKey      *ecdsa.PublicKey
	signCount      uint32
	backupEligible bool
}

// sessionStore は challenge、認証済みセッション、登録済みの資格情報をメモリに保持する。
type sessionStore struct {
	mu                    sync.Mutex
	sessions              map[string]pendingChallenge
	authenticatedSessions map[string]string               // セッション ID → user handle
	credentials           map[string]registeredCredential // キーはパディングなしの base64url credential ID
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

type loginOptions struct {
	Challenge        string                 `json:"challenge"`
	RPID             string                 `json:"rpId"`
	AllowCredentials []credentialDescriptor `json:"allowCredentials"`
	UserVerification string                 `json:"userVerification"`
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
	challenge := s.issueChallenge(w, r, pendingChallenge{
		operation: registerOperation, userHandle: demoUserHandle,
	})
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
		ExcludeCredentials: s.credentialDescriptors(demoUserHandle),
		Attestation:        "none",
	})
}

func (s *sessionStore) handleLoginOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	credentials := s.credentialDescriptors(demoUserHandle)
	if len(credentials) == 0 {
		http.Error(w, "no passkey registered for this account", http.StatusConflict)
		return
	}

	challenge := s.issueChallenge(w, r, pendingChallenge{
		operation:        loginOperation,
		userHandle:       demoUserHandle,
		allowCredentials: credentials,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(loginOptions{
		Challenge:        challenge,
		RPID:             rpID,
		AllowCredentials: credentials,
		UserVerification: "required",
	})
}

func (s *sessionStore) credentialDescriptors(userHandle string) []credentialDescriptor {
	s.mu.Lock()
	defer s.mu.Unlock()

	credentials := make([]credentialDescriptor, 0)
	for id, credential := range s.credentials {
		if credential.userHandle == userHandle {
			credentials = append(credentials, credentialDescriptor{Type: "public-key", ID: id})
		}
	}
	return credentials
}

func (s *sessionStore) handleRegistrationFinish(w http.ResponseWriter, r *http.Request) {
	pending, ok := s.consumeChallenge(r, registerOperation)
	if !ok {
		http.Error(w, "no valid registration challenge", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCredentialBody))
	if err != nil {
		http.Error(w, "could not read registration response", http.StatusBadRequest)
		return
	}
	var credential struct {
		RawID    string `json:"rawId"`
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &credential); err != nil {
		http.Error(w, "invalid registration response JSON", http.StatusBadRequest)
		return
	}

	if _, err := verifyClientData(credential.Response.ClientDataJSON, "webauthn.create", pending.value); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
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

	rawID, err := base64.RawURLEncoding.Strict().DecodeString(credential.RawID)
	if err != nil {
		http.Error(w, "invalid rawId encoding", http.StatusBadRequest)
		return
	}
	publicKey, err := parseRegistrationPublicKey(authData, rawID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id := base64.RawURLEncoding.EncodeToString(rawID)
	registered := registeredCredential{
		userHandle:     pending.userHandle,
		publicKey:      publicKey,
		signCount:      authenticatorSignCount(authData),
		backupEligible: authData[sha256.Size]&flagBackupEligible != 0,
	}
	if !s.saveCredential(id, registered) {
		http.Error(w, "credential ID already registered", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *sessionStore) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	pending, ok := s.consumeChallenge(r, loginOperation)
	if !ok {
		http.Error(w, "no valid login challenge", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCredentialBody))
	if err != nil {
		http.Error(w, "could not read assertion response", http.StatusBadRequest)
		return
	}
	var assertion struct {
		RawID    string `json:"rawId"`
		Response struct {
			UserHandle        *string `json:"userHandle"`
			ClientDataJSON    string  `json:"clientDataJSON"`
			AuthenticatorData string  `json:"authenticatorData"`
			Signature         string  `json:"signature"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &assertion); err != nil {
		http.Error(w, "invalid assertion response JSON", http.StatusBadRequest)
		return
	}

	rawID, err := base64.RawURLEncoding.Strict().DecodeString(assertion.RawID)
	if err != nil || len(rawID) == 0 {
		http.Error(w, "invalid rawId encoding", http.StatusBadRequest)
		return
	}
	id := base64.RawURLEncoding.EncodeToString(rawID)
	if !slices.Contains(pending.allowCredentials, credentialDescriptor{Type: "public-key", ID: id}) {
		http.Error(w, "credential is not allowed for this login", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	credential, ok := s.credentials[id]
	s.mu.Unlock()
	if !ok || credential.userHandle != pending.userHandle {
		http.Error(w, "credential does not belong to this account", http.StatusBadRequest)
		return
	}
	if assertion.Response.UserHandle != nil {
		handle, err := base64.RawURLEncoding.Strict().DecodeString(*assertion.Response.UserHandle)
		if err != nil || base64.RawURLEncoding.EncodeToString(handle) != credential.userHandle {
			http.Error(w, "unexpected userHandle", http.StatusBadRequest)
			return
		}
	}

	rawClientData, err := verifyClientData(assertion.Response.ClientDataJSON, "webauthn.get", pending.value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	authData, err := base64.RawURLEncoding.Strict().DecodeString(assertion.Response.AuthenticatorData)
	if err != nil {
		http.Error(w, "invalid authenticatorData encoding", http.StatusBadRequest)
		return
	}
	if err := verifyLoginAuthenticatorData(authData, credential.backupEligible); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	signature, err := base64.RawURLEncoding.Strict().DecodeString(assertion.Response.Signature)
	if err != nil {
		http.Error(w, "invalid assertion signature encoding", http.StatusBadRequest)
		return
	}
	clientDataHash := sha256.Sum256(rawClientData)
	signedData := slices.Concat(authData, clientDataHash[:])
	digest := sha256.Sum256(signedData)
	if credential.publicKey == nil || !ecdsa.VerifyASN1(credential.publicKey, digest[:], signature) {
		http.Error(w, "invalid assertion signature", http.StatusBadRequest)
		return
	}

	s.updateSignCount(id, authenticatorSignCount(authData))
	s.completeLogin(w, r, credential.userHandle)
	w.WriteHeader(http.StatusNoContent)
}

func (s *sessionStore) completeLogin(w http.ResponseWriter, r *http.Request, userHandle string) {
	id := randomToken()
	previous, _ := r.Cookie(sessionCookieName)

	s.mu.Lock()
	if previous != nil {
		delete(s.sessions, previous.Value)
		delete(s.authenticatedSessions, previous.Value)
	}
	if s.authenticatedSessions == nil {
		s.authenticatedSessions = make(map[string]string)
	}
	s.authenticatedSessions[id] = userHandle
	s.mu.Unlock()

	setSessionCookie(w, r, id)
}

func (s *sessionStore) handleProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	s.mu.Lock()
	userHandle := s.authenticatedSessions[cookie.Value]
	s.mu.Unlock()
	if userHandle != demoUserHandle {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := profileTemplate.Execute(w, demoUsername); err != nil {
		log.Printf("could not render profile: %v", err)
	}
}

func (s *sessionStore) updateSignCount(id string, received uint32) {
	s.mu.Lock()
	credential, ok := s.credentials[id]
	stored := credential.signCount
	if ok && received > stored {
		credential.signCount = received
		s.credentials[id] = credential
	}
	s.mu.Unlock()

	if ok && stored != 0 && received <= stored {
		log.Printf("WebAuthn signCount did not increase: stored=%d received=%d", stored, received)
	}
}

func verifyClientData(encoded, expectedType, expectedChallenge string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid clientDataJSON encoding")
	}
	var clientData struct {
		Type        string          `json:"type"`
		Challenge   string          `json:"challenge"`
		Origin      string          `json:"origin"`
		CrossOrigin bool            `json:"crossOrigin"`
		TopOrigin   json.RawMessage `json:"topOrigin"`
	}
	if err := json.Unmarshal(raw, &clientData); err != nil {
		return nil, errors.New("invalid clientDataJSON")
	}
	if clientData.Type != expectedType || clientData.Challenge != expectedChallenge ||
		clientData.Origin != rpOrigin || clientData.CrossOrigin || len(clientData.TopOrigin) != 0 {
		return nil, errors.New("unexpected client data")
	}
	return raw, nil
}

func (s *sessionStore) saveCredential(id string, credential registeredCredential) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.credentials[id]; exists {
		return false
	}
	if s.credentials == nil {
		s.credentials = make(map[string]registeredCredential)
	}
	s.credentials[id] = credential
	return true
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

func (s *sessionStore) issueChallenge(w http.ResponseWriter, r *http.Request, pending pendingChallenge) string {
	now := time.Now()
	pending.value = randomToken()
	pending.expiresAt = now.Add(challengeLifetime)

	cookie, _ := r.Cookie(sessionCookieName)
	s.mu.Lock()
	for id, session := range s.sessions {
		if !now.Before(session.expiresAt) {
			delete(s.sessions, id)
		}
	}
	if cookie != nil {
		_, hasChallenge := s.sessions[cookie.Value]
		_, authenticated := s.authenticatedSessions[cookie.Value]
		if hasChallenge || authenticated {
			s.sessions[cookie.Value] = pending
			s.mu.Unlock()
			return pending.value
		}
	}
	id := randomToken()
	s.sessions[id] = pending
	s.mu.Unlock()

	setSessionCookie(w, r, id)
	return pending.value
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func randomToken() string {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}
