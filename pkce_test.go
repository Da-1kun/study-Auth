package main

import "testing"

func TestCodeChallenge(t *testing.T) {
	// RFC 7636 Appendix B の S256 テストベクタ。
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const want = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	t.Run("matches RFC 7636 S256 vector", func(t *testing.T) {
		if got := codeChallenge(verifier); got != want {
			t.Errorf("codeChallenge(%q) = %q, want %q", verifier, got, want)
		}
	})

	t.Run("changed verifier does not match original challenge", func(t *testing.T) {
		changedVerifier := verifier[:len(verifier)-1] + "A"
		if got := codeChallenge(changedVerifier); got == want {
			t.Errorf("codeChallenge(%q) matched the original challenge %q", changedVerifier, want)
		}
	})
}
