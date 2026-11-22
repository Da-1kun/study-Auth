package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestExchangeCodeResponse(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    tokenResponse
		wantErr bool
	}{
		{
			name: "decodes token fields",
			body: `{"access_token":"test-access","id_token":"test-id","expires_in":3600,"scope":"openid email profile","token_type":"Bearer"}`,
			want: tokenResponse{
				AccessToken: "test-access",
				IDToken:     "test-id",
				ExpiresIn:   3600,
				Scope:       "openid email profile",
				TokenType:   "Bearer",
			},
		},
		{
			name:    "rejects malformed JSON",
			body:    `{"access_token":`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &app{googleClient: &http.Client{Transport: tokenRoundTripper(func(req *http.Request) (*http.Response, error) {
				defer req.Body.Close()
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(tt.body)),
				}, nil
			})}}

			got, err := a.exchangeCode(context.Background(), "test-code", "test-verifier")
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error: %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("tokens = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRefreshAccessToken(t *testing.T) {
	wantForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"test-refresh"},
		"client_id":     {"test-client"},
		"client_secret": {"test-secret"},
	}
	a := &app{
		cfg: Config{ClientID: "test-client", ClientSecret: "test-secret"},
		googleClient: &http.Client{Transport: tokenRoundTripper(func(req *http.Request) (*http.Response, error) {
			defer req.Body.Close()
			if req.Method != http.MethodPost || req.URL.String() != "https://oauth2.googleapis.com/token" {
				t.Fatalf("unexpected request: %s %s", req.Method, req.URL)
			}
			if err := req.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(req.PostForm, wantForm) {
				t.Fatal("unexpected refresh request form")
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"new-access","expires_in":3599}`)),
			}, nil
		})},
	}
	got, err := a.refreshAccessToken(context.Background(), "test-refresh")
	if err != nil {
		t.Fatal(err)
	}
	if want := (tokenResponse{AccessToken: "new-access", ExpiresIn: 3599}); got != want {
		t.Error("unexpected refresh response")
	}
}
