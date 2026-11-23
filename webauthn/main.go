package main

import (
	_ "embed"
	"log"
	"net/http"
)

const (
	demoUsername = "demo"
	listenAddr   = rpID + ":8081"
	rpOrigin     = "http://" + listenAddr

	// demoUserHandle は一度生成した 32 バイトの乱数を base64url で表した値。
	// 固定アカウントの user.id として、サーバー再起動後も同じ値を使う。
	demoUserHandle = "JuLm0T637Y1GQxrSuJOMvp17YFn8kO0FcxYkK-lIwQw"
)

//go:embed index.html
var indexHTML []byte

func main() {
	sessions := &sessionStore{sessions: make(map[string]pendingChallenge)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register/options", sessions.handleRegistrationOptions)
	mux.HandleFunc("POST /register/finish", sessions.handleRegistrationFinish)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})

	log.Printf("Listening on %s", rpOrigin)
	log.Fatal(http.ListenAndServe(listenAddr, mux))
}
