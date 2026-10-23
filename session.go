package main

import (
	"net/http"
	"sync"
	"time"
)

// sessionCookieName はブラウザに渡す Cookie 名。中身はセッション ID のみで、
// state や code_verifier などの実データはサーバ側メモリにしか置かない。
const sessionCookieName = "sid"

// Session は 1 ブラウザ分のサーバ側状態。
// 以降のステップでフィールドを足していく（State, Nonce, CodeVerifier, ユーザー情報など）。
type Session struct {
	ID        string
	CreatedAt time.Time

	// State は /authorize に付けて送り、/callback で返ってきた値と照合する一回限りの乱数。
	// 「この /callback リクエストは、このブラウザが始めたログインフローの続きである」ことを
	// 保証する（ログイン CSRF 対策）。照合したら空にして使い捨てにする。
	State string
}

// SessionStore はメモリ上のセッション置き場。再起動で消える（学習用途なので割り切る）。
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]*Session)}
}

// Create は新しいセッションを作ってストアに登録し、Cookie をレスポンスに付ける。
func (s *SessionStore) Create(w http.ResponseWriter) *Session {
	sess := &Session{ID: randomToken(32), CreatedAt: time.Now()}

	s.mu.Lock()
	s.sessions[sess.ID] = sess
	s.mu.Unlock()

	s.setCookie(w, sess.ID)
	return sess
}

// Get はリクエストの Cookie からセッションを引く。無ければ nil, false。
func (s *SessionStore) Get(r *http.Request) (*Session, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[c.Value]
	return sess, ok
}

// Delete はセッションを破棄し、ブラウザ側の Cookie も無効化する。
func (s *SessionStore) Delete(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // 即時削除
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// setCookie はセッション ID を Cookie として返す。
//
//   - HttpOnly: JavaScript から document.cookie で読めないようにする（XSS でのセッション ID 窃取対策）
//   - SameSite=Lax: 他サイト起点のリクエストには基本的に Cookie を付けないが、
//     「トップレベルの GET ナビゲーション」には付ける。Google から /callback へ戻ってくる
//     302 リダイレクトはまさにこれなので、Lax でもセッションが引ける。
//     Strict にすると /callback で Cookie が送られず、state 照合ができなくなる。
//   - Secure: 本番(HTTPS)では必須。localhost の http で動かすため今は付けない。
func (s *SessionStore) setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
