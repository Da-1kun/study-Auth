package main

import (
	"context"
	"io"
	"net/http"
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
