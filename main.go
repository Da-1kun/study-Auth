package main

import (
	"log"
	"net/http"
)

type app struct {
	cfg Config
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	a := &app{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleIndex)

	addr := ":" + cfg.Port
	log.Printf("listening on http://localhost%s (redirect_uri=%s)", addr, cfg.RedirectURI)
	log.Fatal(http.ListenAndServe(addr, logRequests(mux)))
}

func (a *app) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html>
<meta charset="utf-8">
<title>study-Auth</title>
<h1>study-Auth</h1>
<p><a href="/login">Google でログイン</a></p>
`))
}
