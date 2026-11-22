package main

import (
	"io"
	"log"
	"net/http"
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
