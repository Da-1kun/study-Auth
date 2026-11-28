package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestProfileRequiresAuthenticatedSession(t *testing.T) {
	tests := []struct {
		name       string
		sessionID  string
		wantStatus int
	}{
		{"no cookie", "", http.StatusFound},
		{"unknown session", "unknown", http.StatusFound},
		{"pending challenge", "pending", http.StatusFound},
		{"authenticated session", "authenticated", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &sessionStore{
				sessions:              map[string]pendingChallenge{"pending": {userHandle: demoUserHandle}},
				authenticatedSessions: map[string]string{"authenticated": demoUserHandle},
			}
			request := httptest.NewRequest(http.MethodGet, "/profile", nil)
			if tt.sessionID != "" {
				request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tt.sessionID})
			}
			response := httptest.NewRecorder()
			store.handleProfile(response, request)
			if response.Code != tt.wantStatus || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status = %d, headers = %v", response.Code, response.Header())
			}
			if tt.wantStatus == http.StatusOK {
				if !strings.Contains(response.Body.String(), "ユーザー名 "+demoUsername) {
					t.Errorf("profile did not show the username: %q", response.Body.String())
				}
			} else if response.Header().Get("Location") != "/" {
				t.Errorf("redirect location = %q, want /", response.Header().Get("Location"))
			}
		})
	}
}

func TestLoginOptions(t *testing.T) {
	tests := []struct {
		name        string
		credentials map[string]registeredCredential
		wantStatus  int
	}{
		{
			name: "no passkey for the account",
			credentials: map[string]registeredCredential{
				"BAUG": {userHandle: "another-user"},
			},
			wantStatus: http.StatusConflict,
		},
		{
			name: "registered passkey for the account",
			credentials: map[string]registeredCredential{
				"AQID": {userHandle: demoUserHandle},
				"BAUG": {userHandle: "another-user"},
			},
			wantStatus: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &sessionStore{
				sessions:    make(map[string]pendingChallenge),
				credentials: tt.credentials,
			}
			request := httptest.NewRequest(http.MethodPost, "/login/options", nil)
			response := httptest.NewRecorder()
			store.handleLoginOptions(response, request)
			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			cookies := response.Result().Cookies()
			if tt.wantStatus == http.StatusConflict {
				if len(cookies) != 0 || len(store.sessions) != 0 {
					t.Fatal("login issued a session without an eligible passkey")
				}
				return
			}

			var options loginOptions
			if err := json.Unmarshal(response.Body.Bytes(), &options); err != nil {
				t.Fatal(err)
			}
			wantCredentials := []credentialDescriptor{{Type: "public-key", ID: "AQID"}}
			if options.RPID != "localhost" || options.UserVerification != "required" ||
				!slices.Equal(options.AllowCredentials, wantCredentials) {
				t.Fatalf("unexpected login options: %+v", options)
			}
			decoded, err := base64.RawURLEncoding.DecodeString(options.Challenge)
			if err != nil || len(decoded) != 32 || len(cookies) != 1 {
				t.Fatal("expected a 32-byte challenge and one session cookie")
			}
			pending := store.sessions[cookies[0].Value]
			if pending.value != options.Challenge || pending.operation != loginOperation || pending.userHandle != demoUserHandle ||
				!slices.Equal(pending.allowCredentials, options.AllowCredentials) {
				t.Fatal("login challenge was not bound to the account and operation")
			}

			request.AddCookie(cookies[0])
			next := httptest.NewRecorder()
			store.handleLoginOptions(next, request)
			if next.Code != http.StatusOK || store.sessions[cookies[0].Value].value == pending.value {
				t.Fatal("repeated login did not replace the challenge")
			}
		})
	}
}

func TestLoginFinishCredentialChecks(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		rawID      string
		userHandle string
		owner      string
		want       int
	}{
		{"matching credential and user handle", "AQID", demoUserHandle, demoUserHandle, http.StatusNoContent},
		{"matching credential without user handle", "AQID", "", demoUserHandle, http.StatusNoContent},
		{"credential registered after options", "BAUG", "", demoUserHandle, http.StatusBadRequest},
		{"credential belongs to another account", "AQID", "", "another-user", http.StatusBadRequest},
		{"unknown credential", "AQID", "", "", http.StatusBadRequest},
		{"invalid credential ID", "!", "", demoUserHandle, http.StatusBadRequest},
		{"wrong user handle", "AQID", "AQID", demoUserHandle, http.StatusBadRequest},
		{"invalid user handle", "AQID", "!", demoUserHandle, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &sessionStore{
				sessions: make(map[string]pendingChallenge),
				credentials: map[string]registeredCredential{
					"AQID": {userHandle: demoUserHandle},
				},
			}
			options := httptest.NewRecorder()
			store.handleLoginOptions(options, httptest.NewRequest(http.MethodPost, "/login/options", nil))
			cookies := options.Result().Cookies()
			if options.Code != http.StatusOK || len(cookies) != 1 {
				t.Fatal("expected login options and a session cookie")
			}
			if tt.owner == "" {
				delete(store.credentials, tt.rawID)
			} else {
				store.credentials[tt.rawID] = registeredCredential{userHandle: tt.owner, publicKey: &privateKey.PublicKey}
			}

			challenge := store.sessions[cookies[0].Value].value
			clientData := fmt.Sprintf(`{"type":"webauthn.get","challenge":%q,"origin":%q}`, challenge, rpOrigin)
			authData := loginAuthenticatorData(rpID, 0x05)
			signature := signLoginAssertion(t, privateKey, clientData, authData)
			body := loginFinishBody(t, tt.rawID, tt.userHandle, clientData, authData, signature)
			request := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(body))
			request.AddCookie(cookies[0])
			response := httptest.NewRecorder()
			store.handleLoginFinish(response, request)
			if response.Code != tt.want {
				t.Errorf("status = %d, want %d, body = %q", response.Code, tt.want, response.Body.String())
			}
			if len(store.sessions) != 0 {
				t.Error("login challenge was not consumed")
			}
		})
	}
}

func TestLoginFinishAssertionData(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const valid = `{"type":"webauthn.get","challenge":"AQID","origin":"http://localhost:8081","crossOrigin":false}`
	tests := []struct {
		name       string
		clientData string
		authData   []byte
		eligible   bool
		want       int
	}{
		{"valid assertion data", valid, loginAuthenticatorData("localhost", 0x05), false, http.StatusNoContent},
		{"valid backup eligibility", valid, loginAuthenticatorData("localhost", 0x1d), true, http.StatusNoContent},
		{"wrong type", strings.Replace(valid, "webauthn.get", "webauthn.create", 1), loginAuthenticatorData("localhost", 0x05), false, http.StatusBadRequest},
		{"wrong challenge", strings.Replace(valid, "AQID", "BAUG", 1), loginAuthenticatorData("localhost", 0x05), false, http.StatusBadRequest},
		{"wrong origin", strings.Replace(valid, "8081", "8080", 1), loginAuthenticatorData("localhost", 0x05), false, http.StatusBadRequest},
		{"cross origin", strings.Replace(valid, "false", "true", 1), loginAuthenticatorData("localhost", 0x05), false, http.StatusBadRequest},
		{"top origin present", strings.TrimSuffix(valid, "}") + `,"topOrigin":"http://localhost:8081"}`, loginAuthenticatorData("localhost", 0x05), false, http.StatusBadRequest},
		{"wrong RP ID hash", valid, loginAuthenticatorData("other.example", 0x05), false, http.StatusBadRequest},
		{"short authenticator data", valid, []byte{1}, false, http.StatusBadRequest},
		{"missing UP", valid, loginAuthenticatorData("localhost", 0x04), false, http.StatusBadRequest},
		{"missing UV", valid, loginAuthenticatorData("localhost", 0x01), false, http.StatusBadRequest},
		{"unexpected AT", valid, loginAuthenticatorData("localhost", 0x45), false, http.StatusBadRequest},
		{"backup eligibility changed", valid, loginAuthenticatorData("localhost", 0x0d), false, http.StatusBadRequest},
		{"backup state without eligibility", valid, loginAuthenticatorData("localhost", 0x15), false, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &sessionStore{
				sessions: map[string]pendingChallenge{
					"login": {
						value: "AQID", operation: loginOperation, userHandle: demoUserHandle,
						expiresAt:        time.Now().Add(time.Minute),
						allowCredentials: []credentialDescriptor{{Type: "public-key", ID: "AQID"}},
					},
				},
				credentials: map[string]registeredCredential{
					"AQID": {userHandle: demoUserHandle, publicKey: &privateKey.PublicKey, backupEligible: tt.eligible},
				},
			}
			signature := signLoginAssertion(t, privateKey, tt.clientData, tt.authData)
			body := loginFinishBody(t, "AQID", "", tt.clientData, tt.authData, signature)
			request := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(body))
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "login"})
			response := httptest.NewRecorder()
			store.handleLoginFinish(response, request)
			if response.Code != tt.want {
				t.Errorf("status = %d, want %d, body = %q", response.Code, tt.want, response.Body.String())
			}
		})
	}
}

func TestLoginFinishSignature(t *testing.T) {
	const clientData = `{ "type": "webauthn.get", "challenge": "AQID", "origin": "http://localhost:8081" }`
	authData := loginAuthenticatorData(rpID, 0x05)
	changedAuthData := slices.Clone(authData)
	changedAuthData[len(changedAuthData)-1] = 1
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := signLoginAssertion(t, privateKey, clientData, authData)
	tests := []struct {
		name       string
		clientData string
		authData   []byte
		signature  string
		wantStatus int
	}{
		{"valid signature using original JSON", clientData, authData, signature, http.StatusNoContent},
		{"wrong signing key", clientData, authData, signLoginAssertion(t, otherKey, clientData, authData), http.StatusBadRequest},
		{"changed JSON serialization", strings.ReplaceAll(clientData, " ", ""), authData, signature, http.StatusBadRequest},
		{"changed authenticator data", clientData, changedAuthData, signature, http.StatusBadRequest},
		{"invalid base64url", clientData, authData, "!", http.StatusBadRequest},
		{"invalid ASN.1", clientData, authData, "AQID", http.StatusBadRequest},
		{"empty signature", clientData, authData, "", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const sessionID = "login"
			store := &sessionStore{
				sessions: map[string]pendingChallenge{
					sessionID: {
						value: "AQID", operation: loginOperation, userHandle: demoUserHandle,
						expiresAt:        time.Now().Add(time.Minute),
						allowCredentials: []credentialDescriptor{{Type: "public-key", ID: "AQID"}},
					},
				},
				credentials: map[string]registeredCredential{
					"AQID": {userHandle: demoUserHandle, publicKey: &privateKey.PublicKey},
				},
				authenticatedSessions: map[string]string{sessionID: demoUserHandle},
			}
			body := loginFinishBody(t, "AQID", "", tt.clientData, tt.authData, tt.signature)
			request := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(body))
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
			response := httptest.NewRecorder()
			store.handleLoginFinish(response, request)
			if response.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d, body = %q", response.Code, tt.wantStatus, response.Body.String())
			}
			cookies := response.Result().Cookies()
			if tt.wantStatus == http.StatusNoContent {
				if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].Value == sessionID {
					t.Fatalf("expected a rotated session cookie, got %v", cookies)
				}
				if len(store.authenticatedSessions) != 1 || store.authenticatedSessions[cookies[0].Value] != demoUserHandle {
					t.Errorf("new session is not bound to the account: %v", store.authenticatedSessions)
				}
				if _, ok := store.authenticatedSessions[sessionID]; ok {
					t.Error("previous session remains authenticated")
				}
			} else if len(cookies) != 0 || len(store.authenticatedSessions) != 1 ||
				store.authenticatedSessions[sessionID] != demoUserHandle {
				t.Error("failed verification changed the authenticated session")
			}
		})
	}
}

func TestLoginFinishSignCount(t *testing.T) {
	const clientData = `{"type":"webauthn.get","challenge":"AQID","origin":"http://localhost:8081"}`
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	previousLogOutput := log.Writer()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousLogOutput) })

	tests := []struct {
		name       string
		stored     uint32
		received   uint32
		valid      bool
		wantStored uint32
		wantLog    bool
	}{
		{"both zero", 0, 0, true, 0, false},
		{"increase from zero", 0, 1, true, 1, false},
		{"increase", 2, 258, true, 258, false},
		{"equal", 3, 3, true, 3, true},
		{"decrease", 3, 2, true, 3, true},
		{"reset to zero", 3, 0, true, 3, true},
		{"invalid signature cannot update count", 3, 4, false, 3, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs.Reset()
			const sessionID = "login"
			store := &sessionStore{
				sessions: map[string]pendingChallenge{
					sessionID: {
						value: "AQID", operation: loginOperation, userHandle: demoUserHandle,
						expiresAt:        time.Now().Add(time.Minute),
						allowCredentials: []credentialDescriptor{{Type: "public-key", ID: "AQID"}},
					},
				},
				credentials: map[string]registeredCredential{
					"AQID": {userHandle: demoUserHandle, publicKey: &privateKey.PublicKey, signCount: tt.stored},
				},
			}
			authData := loginAuthenticatorData(rpID, 0x05)
			binary.BigEndian.PutUint32(authData[33:37], tt.received)
			signature := "AQID"
			wantStatus := http.StatusBadRequest
			if tt.valid {
				signature = signLoginAssertion(t, privateKey, clientData, authData)
				wantStatus = http.StatusNoContent
			}
			body := loginFinishBody(t, "AQID", "", clientData, authData, signature)
			request := httptest.NewRequest(http.MethodPost, "/login/finish", strings.NewReader(body))
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
			response := httptest.NewRecorder()
			store.handleLoginFinish(response, request)
			if response.Code != wantStatus {
				t.Errorf("status = %d, want %d, body = %q", response.Code, wantStatus, response.Body.String())
			}
			if got := store.credentials["AQID"].signCount; got != tt.wantStored {
				t.Errorf("stored signCount = %d, want %d", got, tt.wantStored)
			}
			if logged := strings.Contains(logs.String(), "signCount did not increase"); logged != tt.wantLog {
				t.Errorf("anomaly logged = %t, want %t, log = %q", logged, tt.wantLog, logs.String())
			}
		})
	}
}

func signLoginAssertion(t *testing.T, key *ecdsa.PrivateKey, clientData string, authData []byte) string {
	t.Helper()
	clientHash := sha256.Sum256([]byte(clientData))
	digest := sha256.New()
	digest.Write(authData)
	digest.Write(clientHash[:])
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(signature)
}

func loginAuthenticatorData(rp string, flags byte) []byte {
	hash := sha256.Sum256([]byte(rp))
	return append(hash[:], flags, 0, 0, 0, 0)
}

func loginFinishBody(t *testing.T, rawID, userHandle, clientData string, authData []byte, signature string) string {
	t.Helper()
	data := map[string]string{
		"signature":         signature,
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString([]byte(clientData)),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
	}
	if userHandle != "" {
		data["userHandle"] = userHandle
	}
	response, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"rawId":%q,"response":%s}`, rawID, response)
}

func TestRegistrationOptionsAuthenticatorSelection(t *testing.T) {
	credential := credentialDescriptor{Type: "public-key", ID: "AQID"}
	tests := []struct {
		name        string
		credentials map[string]registeredCredential
		wantExclude []credentialDescriptor
	}{
		{
			name:        "no registered credentials",
			wantExclude: []credentialDescriptor{},
		},
		{
			name: "only credentials belonging to the registration account",
			credentials: map[string]registeredCredential{
				credential.ID: {userHandle: demoUserHandle},
				"BAUG":        {userHandle: "another-user"},
			},
			wantExclude: []credentialDescriptor{credential},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &sessionStore{
				sessions:    make(map[string]pendingChallenge),
				credentials: tt.credentials,
			}
			response := httptest.NewRecorder()
			store.handleRegistrationOptions(response, httptest.NewRequest(http.MethodPost, "/register/options", nil))

			var options struct {
				AuthenticatorSelection struct {
					ResidentKey      string `json:"residentKey"`
					UserVerification string `json:"userVerification"`
				} `json:"authenticatorSelection"`
				ExcludeCredentials []credentialDescriptor `json:"excludeCredentials"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &options); err != nil {
				t.Fatal(err)
			}
			selection := options.AuthenticatorSelection
			if selection.ResidentKey != "required" || selection.UserVerification != "required" {
				t.Errorf("authenticator selection = %+v, want both fields required", selection)
			}
			if options.ExcludeCredentials == nil || !slices.Equal(options.ExcludeCredentials, tt.wantExclude) {
				t.Errorf("excludeCredentials = %#v, want %#v", options.ExcludeCredentials, tt.wantExclude)
			}
		})
	}
}

func TestRegistrationFinishStoresCredentialOnce(t *testing.T) {
	authData, err := parseNoneAttestation(registrationAttestationFixture)
	if err != nil {
		t.Fatal(err)
	}
	authData[32] |= 0x08
	copy(authData[33:37], []byte{0, 0, 1, 2})
	attestation, err := cbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{}, "authData": authData,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(attestation)

	store := &sessionStore{sessions: make(map[string]pendingChallenge)}
	sessions := []string{"session-a", "session-b"}
	for _, id := range sessions {
		store.sessions[id] = pendingChallenge{
			value: id, operation: registerOperation, userHandle: demoUserHandle, expiresAt: time.Now().Add(time.Minute),
		}
	}
	statuses := make(chan int, len(sessions))
	for _, id := range sessions {
		go func() {
			clientData := fmt.Sprintf(`{"type":"webauthn.create","challenge":%q,"origin":%q}`, id, rpOrigin)
			body := strings.Replace(registrationFinishBody(clientData), registrationAttestationFixture, encoded, 1)
			request := httptest.NewRequest(http.MethodPost, "/register/finish", strings.NewReader(body))
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
			response := httptest.NewRecorder()
			store.handleRegistrationFinish(response, request)
			statuses <- response.Code
		}()
	}
	got := []int{<-statuses, <-statuses}
	slices.Sort(got)
	if want := []int{http.StatusNoContent, http.StatusConflict}; !slices.Equal(got, want) {
		t.Fatalf("finish statuses = %v, want %v", got, want)
	}
	credential, ok := store.credentials["AQID"]
	if len(store.credentials) != 1 || !ok || credential.userHandle != demoUserHandle ||
		credential.publicKey == nil || credential.signCount != 258 || !credential.backupEligible {
		t.Fatalf("incorrect stored credential: %+v", credential)
	}
}

func TestRegistrationFinish(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     string
		seed          *pendingChallenge
		issue         bool
		wantStatuses  []int
		wantRemaining int
	}{
		{
			name:         "concurrent requests consume challenge once",
			issue:        true,
			wantStatuses: []int{http.StatusNoContent, http.StatusBadRequest},
		},
		{
			name:         "missing cookie",
			wantStatuses: []int{http.StatusBadRequest},
		},
		{
			name:         "unknown session",
			sessionID:    "unknown",
			wantStatuses: []int{http.StatusBadRequest},
		},
		{
			name:         "expired challenge",
			sessionID:    "expired",
			seed:         &pendingChallenge{operation: registerOperation, expiresAt: time.Now().Add(-time.Minute)},
			wantStatuses: []int{http.StatusBadRequest},
		},
		{
			name:          "wrong operation keeps challenge",
			sessionID:     "login",
			seed:          &pendingChallenge{operation: "login", expiresAt: time.Now().Add(time.Minute)},
			wantStatuses:  []int{http.StatusBadRequest},
			wantRemaining: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &sessionStore{sessions: make(map[string]pendingChallenge)}
			sessionID := tt.sessionID
			if tt.seed != nil {
				store.sessions[sessionID] = *tt.seed
			}
			if tt.issue {
				options := httptest.NewRecorder()
				store.handleRegistrationOptions(options, httptest.NewRequest(http.MethodPost, "/register/options", nil))
				cookies := options.Result().Cookies()
				if len(cookies) != 1 || cookies[0].Name != sessionCookieName {
					t.Fatalf("registration options returned unexpected cookies: %v", cookies)
				}
				sessionID = cookies[0].Value
			}

			statuses := make(chan int, len(tt.wantStatuses))
			body := registrationFinishBody(fmt.Sprintf(`{"type":"webauthn.create","challenge":%q,"origin":%q}`, store.sessions[sessionID].value, rpOrigin))
			for range tt.wantStatuses {
				go func() {
					request := httptest.NewRequest(http.MethodPost, "/register/finish", strings.NewReader(body))
					if sessionID != "" {
						request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
					}
					response := httptest.NewRecorder()
					store.handleRegistrationFinish(response, request)
					statuses <- response.Code
				}()
			}

			got := make([]int, 0, len(tt.wantStatuses))
			for range tt.wantStatuses {
				got = append(got, <-statuses)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.wantStatuses) {
				t.Errorf("finish statuses = %v, want %v", got, tt.wantStatuses)
			}
			if remaining := len(store.sessions); remaining != tt.wantRemaining {
				t.Errorf("remaining sessions = %d, want %d", remaining, tt.wantRemaining)
			}
		})
	}
}

func TestRegistrationFinishClientData(t *testing.T) {
	const valid = `{"type":"webauthn.create","challenge":"AQID","origin":"http://localhost:8081","crossOrigin":false}`
	tests := []struct {
		name string
		body string
		want int
	}{
		{"valid client data", registrationFinishBody(valid), http.StatusNoContent},
		{"rawId mismatch", strings.Replace(registrationFinishBody(valid), `"rawId":"AQID"`, `"rawId":"BAUG"`, 1), http.StatusBadRequest},
		{"short authData header", strings.Replace(registrationFinishBody(valid), registrationAttestationFixture, "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YUEB", 1), http.StatusBadRequest},
		{"missing attestation object", fmt.Sprintf(`{"response":{"clientDataJSON":%q}}`, base64.RawURLEncoding.EncodeToString([]byte(valid))), http.StatusBadRequest},
		{"missing body", "", http.StatusBadRequest},
		{"trailing JSON", registrationFinishBody(valid) + "{}", http.StatusBadRequest},
		{"invalid base64url", `{"response":{"clientDataJSON":"!"}}`, http.StatusBadRequest},
		{"invalid client data JSON", registrationFinishBody("{"), http.StatusBadRequest},
		{"wrong type", registrationFinishBody(strings.Replace(valid, "webauthn.create", "webauthn.get", 1)), http.StatusBadRequest},
		{"wrong challenge", registrationFinishBody(strings.Replace(valid, "AQID", "BAUG", 1)), http.StatusBadRequest},
		{"wrong origin", registrationFinishBody(strings.Replace(valid, "8081", "8080", 1)), http.StatusBadRequest},
		{"cross origin", registrationFinishBody(strings.Replace(valid, "false", "true", 1)), http.StatusBadRequest},
		{"unexpected top origin", registrationFinishBody(strings.TrimSuffix(valid, "}") + `,"topOrigin":"http://localhost:8080"}`), http.StatusBadRequest},
		{"oversized body", registrationFinishBody(valid) + strings.Repeat(" ", 64<<10), http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const sessionID = "registration"
			store := &sessionStore{sessions: map[string]pendingChallenge{
				sessionID: {value: "AQID", operation: registerOperation, expiresAt: time.Now().Add(time.Minute)},
			}}
			request := httptest.NewRequest(http.MethodPost, "/register/finish", strings.NewReader(tt.body))
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionID})
			response := httptest.NewRecorder()
			store.handleRegistrationFinish(response, request)
			if response.Code != tt.want {
				t.Errorf("status = %d, want %d", response.Code, tt.want)
			}
		})
	}
}

// none attestation。credential ID は 01 02 03、公開鍵はテスト用の P-256 の生成点。
const registrationAttestationFixture = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViHSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwECA6UBAgMmIAEhWCBrF9Hy4SxCR_i85uVjpEDydwN9gS3rM6D0oTlF2JjCliJYIE_jQuL-Gn-bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1"

func registrationFinishBody(clientData string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(clientData))
	return fmt.Sprintf(`{"rawId":"AQID","response":{"clientDataJSON":%q,"attestationObject":%q}}`, encoded, registrationAttestationFixture)
}
