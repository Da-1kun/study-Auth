package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestFetchGooglePublicKey(t *testing.T) {
	const jwks = `{"keys":[
		{"kid":"other-key","kty":"RSA","n":"EQ","e":"Aw"},
		{"kid":"current-key","kty":"RSA","n":"AIM","e":"AQAB"},
		{"kid":"invalid-key","kty":"RSA","n":"DQ","e":"AA"},
		{"kid":"ec-key","kty":"EC"}
	]}`
	tests := []struct {
		name    string
		kid     string
		wantN   uint64
		wantE   int
		wantErr bool
	}{
		{name: "selects matching RSA key", kid: "current-key", wantN: 131, wantE: 65537},
		{name: "rejects unknown kid", kid: "unknown-key", wantErr: true},
		{name: "rejects invalid exponent", kid: "invalid-key", wantErr: true},
		{name: "rejects non-RSA key", kid: "ec-key", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &app{googleClient: &http.Client{Transport: tokenRoundTripper(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet || req.URL.String() != "https://www.googleapis.com/oauth2/v3/certs" {
					t.Fatalf("unexpected JWKS request: %s %s", req.Method, req.URL)
				}
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(jwks))}, nil
			})}}
			key, err := a.fetchGooglePublicKey(context.Background(), tt.kid)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error: %t", err, tt.wantErr)
			}
			if !tt.wantErr && (key.N.Uint64() != tt.wantN || key.E != tt.wantE) {
				t.Errorf("RSA key N=%v E=%d, want N=%d E=%d", key.N, key.E, tt.wantN, tt.wantE)
			}
		})
	}
}
