package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

const googleUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

type userInfo struct {
	Subject string `json:"sub"`
	Name    string `json:"name"`
	Email   string `json:"email"`
}

func (a *app) fetchUserInfo(ctx context.Context, accessToken string) (userInfo, error) {
	if accessToken == "" {
		return userInfo{}, fmt.Errorf("Google access token is missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return userInfo{}, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	log.Printf("   [userinfo] %s %s (Authorization: Bearer [redacted])", req.Method, req.URL)

	res, err := a.googleClient.Do(req)
	if err != nil {
		return userInfo{}, err
	}
	defer res.Body.Close()
	log.Printf("   [userinfo] response HTTP %d", res.StatusCode)
	if res.StatusCode != http.StatusOK {
		return userInfo{}, fmt.Errorf("Google UserInfo endpoint returned HTTP %d", res.StatusCode)
	}

	var info userInfo
	if err := json.NewDecoder(res.Body).Decode(&info); err != nil {
		return userInfo{}, fmt.Errorf("decode Google UserInfo response: %w", err)
	}
	return info, nil
}
