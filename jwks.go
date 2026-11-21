package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

const googleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"

func (a *app) fetchGooglePublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleJWKSURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := a.googleClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Google JWKS endpoint returned HTTP %d", res.StatusCode)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode Google JWKS: %w", err)
	}
	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Kty == "RSA" {
			return decodeRSAPublicKey(key.N, key.E)
		}
	}
	return nil, fmt.Errorf("no matching RSA key in Google JWKS")
}

func decodeRSAPublicKey(n, e string) (*rsa.PublicKey, error) {
	modulusBytes, err := base64.RawURLEncoding.DecodeString(n)
	if err != nil {
		return nil, fmt.Errorf("decode RSA modulus: %w", err)
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	if modulus.Bit(0) == 0 {
		return nil, fmt.Errorf("RSA modulus must be positive and odd")
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(e)
	if err != nil {
		return nil, fmt.Errorf("decode RSA exponent: %w", err)
	}
	exponent := new(big.Int).SetBytes(exponentBytes)
	if exponent.BitLen() > 31 || exponent.BitLen() < 2 || exponent.Bit(0) == 0 {
		return nil, fmt.Errorf("invalid RSA public exponent")
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}
