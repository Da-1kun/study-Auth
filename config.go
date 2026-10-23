package main

import (
	"fmt"
	"os"
)

// Config はアプリの設定。すべて環境変数から読む。
type Config struct {
	ClientID     string // Google が発行した client_id
	ClientSecret string // Google が発行した client_secret（/token の POST で使う。ブラウザには絶対に出さない）
	RedirectURI  string // /authorize に渡し、かつ Google 側に登録済みでなければならない URI
	Port         string
}

func loadConfig() (Config, error) {
	cfg := Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURI:  getenv("REDIRECT_URI", "http://localhost:8080/callback"),
		Port:         getenv("PORT", "8080"),
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return cfg, fmt.Errorf("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set (see .env.example)")
	}
	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
