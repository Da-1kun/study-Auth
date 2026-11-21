package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHandleCallbackAuthorizationError(t *testing.T) {
	const sessionState = "login-state"
	tests := []struct {
		name      string
		query     url.Values
		wantCode  int
		wantBody  string
		wantState string
	}{
		{
			name:     "consent denied",
			query:    url.Values{"state": {sessionState}, "error": {"access_denied"}},
			wantCode: http.StatusBadRequest,
			wantBody: "Google の認可に失敗しました (access_denied)\n",
		},
		{
			name:      "error with mismatched state",
			query:     url.Values{"state": {"unexpected"}, "error": {"access_denied"}},
			wantCode:  http.StatusBadRequest,
			wantBody:  "state が一致しません\n",
			wantState: sessionState,
		},
		{
			name:     "successful authorization",
			query:    url.Values{"state": {sessionState}, "code": {"authorization-code"}},
			wantCode: http.StatusOK,
			wantBody: "state OK\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &app{sessions: NewSessionStore()}
			login := httptest.NewRecorder()
			sess := a.sessions.Create(login)
			sess.State = sessionState

			req := httptest.NewRequest(http.MethodGet, "/callback?"+tt.query.Encode(), nil)
			for _, cookie := range login.Result().Cookies() {
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			a.handleCallback(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if got := rec.Body.String(); got != tt.wantBody {
				t.Errorf("body = %q, want %q", got, tt.wantBody)
			}
			if sess.State != tt.wantState {
				t.Errorf("session state = %q, want %q", sess.State, tt.wantState)
			}
		})
	}
}

func TestHandleLoginRedirect(t *testing.T) {
	sessionQuery := map[string]func(*Session) string{
		"state":          func(sess *Session) string { return sess.State },
		"nonce":          func(sess *Session) string { return sess.Nonce },
		"code_challenge": func(sess *Session) string { return codeChallenge(sess.CodeVerifier) },
	}
	type expected struct {
		status       int
		endpoint     string
		query        map[string]string
		sessionQuery map[string]func(*Session) string
	}
	tests := []struct {
		name string
		cfg  Config
		want expected
	}{
		{
			name: "localhost callback",
			cfg: Config{
				ClientID:     "test-client.apps.googleusercontent.com",
				ClientSecret: "test-secret",
				RedirectURI:  "http://localhost:8080/callback",
			},
			want: expected{
				status:   http.StatusFound,
				endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
				query: map[string]string{
					"client_id":             "test-client.apps.googleusercontent.com",
					"redirect_uri":          "http://localhost:8080/callback",
					"response_type":         "code",
					"scope":                 "openid email profile",
					"code_challenge_method": "S256",
				},
				sessionQuery: sessionQuery,
			},
		},
		{
			name: "callback with query parameters",
			cfg: Config{
				ClientID:     "another-client.apps.googleusercontent.com",
				ClientSecret: "another-secret",
				RedirectURI:  "https://example.com/callback?source=a%2Bb&return=%2Fhome",
			},
			want: expected{
				status:   http.StatusFound,
				endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
				query: map[string]string{
					"client_id":             "another-client.apps.googleusercontent.com",
					"redirect_uri":          "https://example.com/callback?source=a%2Bb&return=%2Fhome",
					"response_type":         "code",
					"scope":                 "openid email profile",
					"code_challenge_method": "S256",
				},
				sessionQuery: sessionQuery,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &app{cfg: tt.cfg, sessions: NewSessionStore()}
			rec := httptest.NewRecorder()
			a.handleLogin(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
			res := rec.Result()
			defer res.Body.Close()
			if res.StatusCode != tt.want.status {
				t.Fatalf("status = %d, want %d", res.StatusCode, tt.want.status)
			}

			callback := httptest.NewRequest(http.MethodGet, "/callback", nil)
			for _, cookie := range res.Cookies() {
				callback.AddCookie(cookie)
			}
			sess, ok := a.sessions.Get(callback)
			if !ok || sess.State == "" || sess.Nonce == "" || sess.CodeVerifier == "" {
				t.Fatal("login did not save state, nonce and verifier in the cookie's session")
			}

			loc, err := res.Location()
			if err != nil {
				t.Fatal(err)
			}
			query := loc.Query()
			endpoint := *loc
			endpoint.RawQuery = ""
			if got := endpoint.String(); got != tt.want.endpoint {
				t.Errorf("authorization endpoint = %q, want %q", got, tt.want.endpoint)
			}
			wantCount := len(tt.want.query) + len(tt.want.sessionQuery)
			if len(query) != wantCount {
				t.Errorf("authorization query has %d keys, want %d", len(query), wantCount)
			}
			checkQuery := func(key, want string) {
				if got := query[key]; len(got) != 1 || got[0] != want {
					t.Errorf("authorization query has an incorrect %s parameter", key)
				}
			}
			for key, want := range tt.want.query {
				checkQuery(key, want)
			}
			for key, expectedValue := range tt.want.sessionQuery {
				checkQuery(key, expectedValue(sess))
			}
		})
	}
}
