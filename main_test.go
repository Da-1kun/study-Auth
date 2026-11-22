package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type tokenRoundTripper func(*http.Request) (*http.Response, error)

func (f tokenRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHandleCallback(t *testing.T) {
	const sessionState = "login-state"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	payload := fmt.Sprintf(`{"iss":"https://accounts.google.com","aud":"test-client","exp":%d,"nonce":"test-nonce","sub":"123"}`, time.Now().Add(time.Hour).Unix())
	signingInput := encode([]byte(`{"alg":"RS256","kid":"test-key"}`)) + "." + encode([]byte(payload))
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	tokenBody := fmt.Sprintf(`{"access_token":"test-access-token","expires_in":3600,"id_token":%q}`, signingInput+"."+encode(signature))
	tokenBodyWithRefresh := strings.TrimSuffix(tokenBody, "}") + `,"refresh_token":"new-refresh-token"}`
	jwks := fmt.Sprintf(`{"keys":[{"kid":"test-key","kty":"RSA","n":%q,"e":%q}]}`,
		encode(key.N.Bytes()), encode(big.NewInt(int64(key.E)).Bytes()))

	type userInfoRequest struct {
		method, endpoint, authorization string
	}
	wantUserInfo := userInfoRequest{"GET", "https://openidconnect.googleapis.com/v1/userinfo", "Bearer test-access-token"}
	wantForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"authorization-code"},
		"redirect_uri":  {"http://localhost:8080/callback"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
		"code_verifier": {"test-verifier"},
	}
	tests := []struct {
		userInfoBody    string
		wantUserInfo    userInfoRequest
		name            string
		query           url.Values
		wantCode        int
		wantBody        string
		wantLocation    string
		wantState       string
		wantSession     userInfo
		savedRefresh    string
		wantRefresh     string
		wantForm        url.Values
		wantRefreshForm url.Values
		refreshBody     string
		tokenCode       int
		tokenBody       string
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
			name:         "successful authorization stores the refresh token",
			query:        url.Values{"state": {sessionState}, "code": {"authorization-code"}},
			wantCode:     http.StatusFound,
			wantBody:     "<a href=\"/profile\">Found</a>.\n\n",
			wantLocation: "/profile",
			wantForm:     wantForm,
			tokenCode:    http.StatusOK,
			tokenBody:    tokenBodyWithRefresh,
			wantRefresh:  "new-refresh-token",
			userInfoBody: `{"sub":"123","name":"Test User","email":"user@example.com"}`,
			wantUserInfo: wantUserInfo,
			wantSession:  userInfo{Subject: "123", Name: "Test User", Email: "user@example.com"},
		},
		{
			name:         "missing refresh token preserves the saved token",
			query:        url.Values{"state": {sessionState}, "code": {"authorization-code"}},
			wantCode:     http.StatusFound,
			wantBody:     "<a href=\"/profile\">Found</a>.\n\n",
			wantLocation: "/profile",
			wantForm:     wantForm,
			tokenCode:    http.StatusOK,
			tokenBody:    tokenBody,
			userInfoBody: `{"sub":"123","name":"Test User","email":"user@example.com"}`,
			wantUserInfo: wantUserInfo,
			wantSession:  userInfo{Subject: "123", Name: "Test User", Email: "user@example.com"},
			savedRefresh: "saved-refresh-token",
			wantRefresh:  "saved-refresh-token",
		},
		{
			name:         "expired token refreshes before calling UserInfo",
			query:        url.Values{"state": {sessionState}, "code": {"authorization-code"}},
			wantCode:     http.StatusFound,
			wantBody:     "<a href=\"/profile\">Found</a>.\n\n",
			wantLocation: "/profile",
			wantForm:     wantForm,
			tokenCode:    http.StatusOK,
			tokenBody:    strings.Replace(tokenBody, `"expires_in":3600`, `"expires_in":0`, 1),
			savedRefresh: "saved-refresh-token",
			wantRefresh:  "rotated-refresh-token",
			wantRefreshForm: url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {"saved-refresh-token"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
			},
			refreshBody:  `{"access_token":"refreshed-access-token","expires_in":3600,"refresh_token":"rotated-refresh-token"}`,
			userInfoBody: `{"sub":"123","name":"Test User","email":"user@example.com"}`,
			wantUserInfo: userInfoRequest{"GET", "https://openidconnect.googleapis.com/v1/userinfo", "Bearer refreshed-access-token"},
			wantSession:  userInfo{Subject: "123", Name: "Test User", Email: "user@example.com"},
		},
		{
			name:     "mismatched UserInfo subject",
			query:    url.Values{"state": {sessionState}, "code": {"authorization-code"}},
			wantCode: http.StatusBadGateway,
			wantBody: "Google のユーザー情報と ID トークンの sub が一致しません\n",
			wantForm: url.Values{
				"grant_type":    {"authorization_code"},
				"code":          {"authorization-code"},
				"redirect_uri":  {"http://localhost:8080/callback"},
				"client_id":     {"test-client"},
				"client_secret": {"test-secret"},
				"code_verifier": {"test-verifier"},
			},
			tokenCode:    http.StatusOK,
			tokenBody:    tokenBodyWithRefresh,
			savedRefresh: "saved-refresh-token",
			wantRefresh:  "saved-refresh-token",
			userInfoBody: `{"sub":"456"}`,
			wantUserInfo: wantUserInfo,
		},
		{
			name:     "missing authorization code",
			query:    url.Values{"state": {sessionState}},
			wantCode: http.StatusBadRequest,
			wantBody: "認可コードがありません\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sentForm, sentRefreshForm url.Values
			var sentUserInfo userInfoRequest
			a := &app{
				cfg: Config{
					ClientID: "test-client", ClientSecret: "test-secret",
					RedirectURI: "http://localhost:8080/callback",
				},
				sessions: NewSessionStore(),
				googleClient: &http.Client{Transport: tokenRoundTripper(func(req *http.Request) (*http.Response, error) {
					if req.Method == http.MethodGet && req.URL.String() == "https://www.googleapis.com/oauth2/v3/certs" {
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(jwks))}, nil
					}
					if req.URL.Host == "openidconnect.googleapis.com" {
						sentUserInfo = userInfoRequest{req.Method, req.URL.String(), req.Header.Get("Authorization")}
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.userInfoBody))}, nil
					}
					if req.Body == nil {
						t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
					}
					defer req.Body.Close()
					if req.Method != http.MethodPost || req.URL.String() != "https://oauth2.googleapis.com/token" {
						t.Errorf("unexpected token request: %s %s", req.Method, req.URL)
					}
					if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
						t.Errorf("unexpected token request content type: %q", got)
					}
					if err := req.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if req.PostForm.Get("grant_type") == "refresh_token" {
						sentRefreshForm = req.PostForm
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tt.refreshBody))}, nil
					}
					sentForm = req.PostForm
					return &http.Response{StatusCode: tt.tokenCode, Body: io.NopCloser(strings.NewReader(tt.tokenBody))}, nil
				})},
			}
			if tt.savedRefresh != "" {
				a.sessions.refreshTokens["123"] = tt.savedRefresh
			}
			login := httptest.NewRecorder()
			sess := a.sessions.Create(login)
			sess.State = sessionState
			sess.CodeVerifier = "test-verifier"
			sess.Nonce = "test-nonce"

			req := httptest.NewRequest(http.MethodGet, "/callback?"+tt.query.Encode(), nil)
			for _, cookie := range login.Result().Cookies() {
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			a.handleCallback(rec, req)

			wantRefreshTokens := map[string]string{}
			if tt.wantRefresh != "" {
				wantRefreshTokens["123"] = tt.wantRefresh
			}
			if !reflect.DeepEqual(a.sessions.refreshTokens, wantRefreshTokens) {
				t.Error("unexpected refresh tokens in the session store")
			}

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if got := rec.Body.String(); got != tt.wantBody {
				t.Errorf("body = %q, want %q", got, tt.wantBody)
			}
			if got := rec.Header().Get("Location"); got != tt.wantLocation {
				t.Errorf("Location = %q, want %q", got, tt.wantLocation)
			}
			if sess.State != tt.wantState {
				t.Errorf("session state = %q, want %q", sess.State, tt.wantState)
			}
			rotated := tt.wantSession.Subject != ""
			if _, ok := a.sessions.Get(req); ok == rotated {
				t.Errorf("previous session exists = %t, want %t", ok, !rotated)
			}
			res := rec.Result()
			defer res.Body.Close()
			cookies := res.Cookies()
			if !rotated {
				if len(cookies) != 0 {
					t.Error("failed callback issued a new cookie")
				}
			} else {
				if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].Value == sess.ID {
					t.Fatal("successful callback did not issue a fresh session cookie")
				}
				next := httptest.NewRequest(http.MethodGet, "/", nil)
				next.AddCookie(cookies[0])
				current, ok := a.sessions.Get(next)
				if !ok {
					t.Fatal("new session cookie does not resolve to a session")
				}
				if current.UserInfo != tt.wantSession {
					t.Errorf("session UserInfo = %+v, want %+v", current.UserInfo, tt.wantSession)
				}
				if current.State != "" || current.CodeVerifier != "" || current.Nonce != "" {
					t.Error("new session retained temporary login data")
				}
			}
			if sentUserInfo != tt.wantUserInfo {
				t.Errorf("UserInfo request = %+v, want %+v", sentUserInfo, tt.wantUserInfo)
			}
			if !reflect.DeepEqual(sentRefreshForm, tt.wantRefreshForm) {
				t.Error("unexpected refresh token request form")
			}
			if !reflect.DeepEqual(sentForm, tt.wantForm) {
				t.Errorf("token request form = %v, want %v", sentForm, tt.wantForm)
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
					"access_type":           "offline",
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
					"access_type":           "offline",
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

func TestHandleProfile(t *testing.T) {
	tests := []struct {
		name         string
		hasSession   bool
		info         userInfo
		wantCode     int
		wantLocation string
		wantContent  []string
	}{
		{
			name:         "no session",
			wantCode:     http.StatusFound,
			wantLocation: "/login",
		},
		{
			name:         "login in progress",
			hasSession:   true,
			wantCode:     http.StatusFound,
			wantLocation: "/login",
		},
		{
			name:        "authenticated",
			hasSession:  true,
			info:        userInfo{Subject: "123", Name: "<b>Test User</b>", Email: "user@example.com"},
			wantCode:    http.StatusOK,
			wantContent: []string{"<dd>&lt;b&gt;Test User&lt;/b&gt;</dd>", "<dd>user@example.com</dd>"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &app{sessions: NewSessionStore()}
			req := httptest.NewRequest(http.MethodGet, "/profile", nil)
			if tt.hasSession {
				login := httptest.NewRecorder()
				sess := a.sessions.Create(login)
				sess.UserInfo = tt.info
				res := login.Result()
				defer res.Body.Close()
				for _, cookie := range res.Cookies() {
					req.AddCookie(cookie)
				}
			}
			rec := httptest.NewRecorder()
			a.handleProfile(rec, req)

			if rec.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantCode)
			}
			if got := rec.Header().Get("Location"); got != tt.wantLocation {
				t.Errorf("Location = %q, want %q", got, tt.wantLocation)
			}
			for _, content := range tt.wantContent {
				if !strings.Contains(rec.Body.String(), content) {
					t.Errorf("body does not contain %q", content)
				}
			}
		})
	}
}

func TestHandleLogout(t *testing.T) {
	a := &app{sessions: NewSessionStore()}
	login := httptest.NewRecorder()
	sess := a.sessions.Create(login)
	sess.UserInfo = userInfo{Subject: "123"}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.ID})
	rec := httptest.NewRecorder()
	a.handleLogout(rec, req)

	res := rec.Result()
	defer res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Errorf("logout returned status %d and Location %q", res.StatusCode, res.Header.Get("Location"))
	}
	cookies := res.Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookieName || cookies[0].Path != "/" || cookies[0].MaxAge != -1 {
		t.Error("logout did not send a deletion cookie for the session")
	}
	if _, ok := a.sessions.Get(req); ok {
		t.Error("old session cookie still resolves after logout")
	}
}
