package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const googleTokenURL = "https://oauth2.googleapis.com/token"

func (a *app) exchangeCode(ctx context.Context, code, verifier string) error {
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
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := a.tokenClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Google token endpoint returned HTTP %d", res.StatusCode)
	}
	return nil
}
