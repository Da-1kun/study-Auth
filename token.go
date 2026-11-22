package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const googleTokenURL = "https://oauth2.googleapis.com/token"

type tokenResponse struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

func (a *app) exchangeCode(ctx context.Context, code, verifier string) (tokenResponse, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {a.cfg.RedirectURI},
		"client_id":     {a.cfg.ClientID},
		"client_secret": {a.cfg.ClientSecret},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, googleTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// リクエスト本文はエンコード済みなので、以降の form の変更は送信内容に影響しない。
	for _, key := range []string{"code", "client_secret", "code_verifier"} {
		form.Set(key, "[redacted]")
	}
	if dump, err := httputil.DumpRequestOut(req, false); err == nil {
		log.Printf("   [token] request\n%s%s", dump, form.Encode())
	}

	res, err := a.googleClient.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer res.Body.Close()
	logResponse := *res
	logResponse.Header = http.Header{"Content-Type": res.Header.Values("Content-Type")}
	if dump, err := httputil.DumpResponse(&logResponse, false); err == nil {
		log.Printf("   [token] response\n%s", dump)
	}
	if res.StatusCode != http.StatusOK {
		return tokenResponse{}, fmt.Errorf("Google token endpoint returned HTTP %d", res.StatusCode)
	}

	var tokens tokenResponse
	if err := json.NewDecoder(res.Body).Decode(&tokens); err != nil {
		return tokenResponse{}, fmt.Errorf("decode Google token response: %w", err)
	}
	loggedTokens := tokenResponse{
		AccessToken: "[redacted]",
		IDToken:     "[redacted]",
		ExpiresIn:   tokens.ExpiresIn,
		Scope:       tokens.Scope,
		TokenType:   tokens.TokenType,
	}
	if tokens.RefreshToken != "" {
		loggedTokens.RefreshToken = "[redacted]"
	}
	body, _ := json.Marshal(loggedTokens)
	log.Printf("   [token] response JSON: %s", body)
	return tokens, nil
}
