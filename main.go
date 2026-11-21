package main

import (
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

const googleAuthorizeURL = "https://accounts.google.com/o/oauth2/v2/auth"

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
	mux.HandleFunc("GET /callback", a.handleCallback)

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
// ログインに必要な値を新しいセッションに保存し、Google の認可画面へリダイレクトする。
func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 既存セッションがあっても作り直す（前回の途中状態を引きずらない）
	sess := a.sessions.Create(w)
	sess.State = randomToken(32)
	// 32 バイトの乱数をパディングなしの base64url にすると 43 文字になる。
	sess.CodeVerifier = randomToken(32)
	sess.Nonce = randomToken(32)

	query := url.Values{
		"client_id":             {a.cfg.ClientID},
		"redirect_uri":          {a.cfg.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {sess.State},
		"nonce":                 {sess.Nonce},
		"code_challenge":        {codeChallenge(sess.CodeVerifier)},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, googleAuthorizeURL+"?"+query.Encode(), http.StatusFound)
}

// handleCallback は Google からリダイレクトで戻ってくる先。
// state を照合し、Google が返した認可エラーがあれば表示する。
func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	// 1. Cookie からセッションを引く。
	//    無い = このブラウザは /login を通っていない（または Cookie が送られていない）。
	//    SameSite=Strict にするとここで失敗するので、試すと違いが分かる。
	sess, ok := a.sessions.Get(r)
	if !ok {
		log.Printf("   [callback] no session cookie")
		http.Error(w, "セッションがありません。/login からやり直してください", http.StatusBadRequest)
		return
	}

	// 2. state を照合する。
	//    ConstantTimeCompare を使うのは、比較にかかる時間から一致した文字数を推測される
	//    タイミング攻撃を避けるため（== は先頭から比べて不一致で即終了する）。
	got := q.Get("state")
	want := sess.State
	if want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		log.Printf("   [callback] state mismatch: got=%q want=%q", got, want)
		http.Error(w, "state が一致しません", http.StatusBadRequest)
		return
	}

	// 3. 照合に成功した state は使い捨てにする。
	//    同じ URL を再度開かれても（リプレイ）、もう一致しないようにする。
	sess.State = ""
	log.Printf("   [callback] state OK (session=%s)", sess.ID)

	if authError := q.Get("error"); authError != "" {
		http.Error(w, fmt.Sprintf("Google の認可に失敗しました (%s)", authError), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "state OK")
}
