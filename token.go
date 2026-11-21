package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const googleTokenURL = "https://oauth2.googleapis.com/token"

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
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

	res, err := a.tokenClient.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return tokenResponse{}, fmt.Errorf("Google token endpoint returned HTTP %d", res.StatusCode)
	}

	var tokens tokenResponse
	if err := json.NewDecoder(res.Body).Decode(&tokens); err != nil {
		return tokenResponse{}, fmt.Errorf("decode Google token response: %w", err)
	}
	return tokens, nil
}
