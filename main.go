package main

import (
	"fmt"
	"log"
	"net/http"
)

type app struct {
	cfg      Config
	sessions *SessionStore
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	a := &app{cfg: cfg, sessions: NewSessionStore()}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleIndex)
	mux.HandleFunc("GET /login", a.handleLogin)

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

// handleLogin はログインフローの開始点。
// ブラウザごとに新しいセッションを作り、state を生成して保存する。
// 現時点では確認用に state を本文に出すだけ。Step 3 で /authorize への 302 に置き換える。
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 既存セッションがあっても作り直す（前回の途中状態を引きずらない）
	sess := a.sessions.Create(w)
	sess.State = randomToken(32)

	log.Printf("   [login] session=%s state=%s", sess.ID, sess.State)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "state=%s\n", sess.State)
}
