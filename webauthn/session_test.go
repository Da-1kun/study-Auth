package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

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
			if pending.value != options.Challenge || pending.operation != loginOperation || pending.userHandle != demoUserHandle {
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
