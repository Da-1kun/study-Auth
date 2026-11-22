package main

import (
	"io"
	"log"
	"net/http"
)

const (
	demoUsername = "demo"

	// demoUserHandle は一度生成した 32 バイトの乱数を base64url で表した値。
	// 固定アカウントの user.id として、サーバー再起動後も同じ値を使う。
	demoUserHandle = "JuLm0T637Y1GQxrSuJOMvp17YFn8kO0FcxYkK-lIwQw"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "WebAuthn 学習用サーバー\n")
	})

	const addr = "localhost:8081"
	log.Printf("Listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
