package main

import (
	"crypto/rand"
	"encoding/base64"
)

// randomToken は暗号論的に安全な乱数 n バイトを base64url（パディング無し）で返す。
// セッション ID / state / nonce / code_verifier はすべてこれで作る。
//
// math/rand は種が分かれば再現できるので使わない。state が推測可能だと
// 攻撃者が正しい state 付きの /callback URL を作れてしまい、CSRF 対策にならない。
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand の失敗は OS レベルの異常で復旧不能なので panic でよい
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
