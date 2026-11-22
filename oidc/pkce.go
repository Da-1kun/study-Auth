package main

import (
	"crypto/sha256"
	"encoding/base64"
)

// codeChallenge は PKCE の S256 方式で verifier から challenge を計算する。
func codeChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
