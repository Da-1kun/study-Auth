package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

type decodedIDToken struct {
	Header  map[string]json.RawMessage
	Payload map[string]json.RawMessage
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
	return decodedIDToken{Header: header, Payload: payload}, nil
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
