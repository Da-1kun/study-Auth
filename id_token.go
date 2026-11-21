package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type decodedIDToken struct {
	Header  map[string]json.RawMessage
	Payload map[string]json.RawMessage

	signingInput     string
	encodedSignature string
}

// decodeIDToken は RS256 の JWT の内容を読み取る。署名とクレームの検証は後続の処理で行う。
func decodeIDToken(raw string) (decodedIDToken, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return decodedIDToken{}, fmt.Errorf("ID token must contain three segments")
	}

	header, err := decodeJWTObject(parts[0])
	if err != nil {
		return decodedIDToken{}, fmt.Errorf("decode ID token header: %w", err)
	}
	var alg string
	if err := json.Unmarshal(header["alg"], &alg); err != nil || alg != "RS256" {
		return decodedIDToken{}, fmt.Errorf("ID token header alg must be RS256")
	}

	payload, err := decodeJWTObject(parts[1])
	if err != nil {
		return decodedIDToken{}, fmt.Errorf("decode ID token payload: %w", err)
	}
	return decodedIDToken{
		Header:           header,
		Payload:          payload,
		signingInput:     parts[0] + "." + parts[1],
		encodedSignature: parts[2],
	}, nil
}

func (token decodedIDToken) verifySignature(key *rsa.PublicKey) error {
	signature, err := base64.RawURLEncoding.DecodeString(token.encodedSignature)
	if err != nil {
		return fmt.Errorf("decode ID token signature: %w", err)
	}
	digest := sha256.Sum256([]byte(token.signingInput))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature)
}

func decodeJWTObject(encoded string) (map[string]json.RawMessage, error) {
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, fmt.Errorf("expected a JSON object")
	}
	return object, nil
}
