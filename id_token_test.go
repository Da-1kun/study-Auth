package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestDecodeIDToken(t *testing.T) {
	const header = "eyJhbGciOiJSUzI1NiJ9"
	const payload = "eyJzdWIiOiIxMjMifQ"
	tests := []struct {
		name    string
		token   string
		want    decodedIDToken
		wantErr bool
	}{
		{
			name:  "decodes header and payload",
			token: header + "." + payload + ".c2ln",
			want: decodedIDToken{
				Header:           map[string]json.RawMessage{"alg": json.RawMessage(`"RS256"`)},
				Payload:          map[string]json.RawMessage{"sub": json.RawMessage(`"123"`)},
				signingInput:     header + "." + payload,
				encodedSignature: "c2ln",
			},
		},
		{name: "missing segment", token: header + "." + payload, wantErr: true},
		{name: "invalid base64url", token: "!" + "." + payload + ".c2ln", wantErr: true},
		{name: "invalid JSON", token: header + ".ew.c2ln", wantErr: true},
		{name: "payload is not an object", token: header + ".bnVsbA.c2ln", wantErr: true},
		{
			name:    "rejects none algorithm",
			token:   base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + payload + ".c2ln",
			wantErr: true,
		},
		{
			name:    "rejects another algorithm",
			token:   base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." + payload + ".c2ln",
			wantErr: true,
		},
		{
			name:    "rejects missing algorithm",
			token:   "e30." + payload + ".c2ln",
			wantErr: true,
		},
		{
			name:    "rejects non-string algorithm",
			token:   base64.RawURLEncoding.EncodeToString([]byte(`{"alg":256}`)) + "." + payload + ".c2ln",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeIDToken(tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error: %t", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("decoded token = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestVerifyIDToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_800_000_000, 0)
	encode := base64.RawURLEncoding.EncodeToString
	header := encode([]byte(`{"alg":"RS256"}`))
	signingInput := func(audience string, expiry time.Time, subject string) string {
		payload := fmt.Sprintf(`{"iss":"https://accounts.google.com","aud":%q,"exp":%d,"nonce":"test-nonce","sub":%q}`,
			audience, expiry.Unix(), subject)
		return header + "." + encode([]byte(payload))
	}
	sign := func(input string) string {
		digest := sha256.Sum256([]byte(input))
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		return encode(signature)
	}

	expires := now.Add(time.Hour)
	validInput := signingInput("test-client", expires, "test-user")
	validSignature := sign(validInput)
	expiredInput := signingInput("test-client", now.Add(-time.Second), "test-user")
	wrongAudienceInput := signingInput("other-client", expires, "test-user")

	tests := []struct {
		name             string
		token            string
		wantSignatureErr bool
		wantClaimsErr    string
	}{
		{
			name:  "valid token",
			token: validInput + "." + validSignature,
		},
		{
			name:             "payload changed after signing",
			token:            signingInput("test-client", expires, "changed-user") + "." + validSignature,
			wantSignatureErr: true,
		},
		{
			name:          "expired token",
			token:         expiredInput + "." + sign(expiredInput),
			wantClaimsErr: "ID token expiration is missing, invalid, or elapsed",
		},
		{
			name:          "audience mismatch",
			token:         wrongAudienceInput + "." + sign(wrongAudienceInput),
			wantClaimsErr: "invalid ID token audience",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := decodeIDToken(tt.token)
			if err != nil {
				t.Fatal(err)
			}
			err = token.verifySignature(&key.PublicKey)
			if (err != nil) != tt.wantSignatureErr {
				t.Fatalf("signature error = %v, want error: %t", err, tt.wantSignatureErr)
			}
			if tt.wantSignatureErr {
				return
			}
			err = token.verifyClaims("test-client", "test-nonce", now)
			var gotClaimsErr string
			if err != nil {
				gotClaimsErr = err.Error()
			}
			if gotClaimsErr != tt.wantClaimsErr {
				t.Errorf("claims error = %q, want %q", gotClaimsErr, tt.wantClaimsErr)
			}
		})
	}
}
