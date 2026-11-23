package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

const (
	authenticatorDataHeaderSize = sha256.Size + 1 + 4 // RP ID hash, flags, signCount

	flagUserPresent            = 1 << 0
	flagUserVerified           = 1 << 2
	flagAttestedCredentialData = 1 << 6
)

func verifyRegistrationAuthenticatorData(authData []byte) error {
	if len(authData) < authenticatorDataHeaderSize {
		return errors.New("authData header is too short")
	}

	expectedRPIDHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(authData[:sha256.Size], expectedRPIDHash[:]) {
		return errors.New("authData RP ID hash mismatch")
	}

	const requiredFlags = flagUserPresent | flagUserVerified | flagAttestedCredentialData
	flags := authData[sha256.Size]
	if flags&requiredFlags != requiredFlags {
		return errors.New("authData must set UP, UV, and AT flags")
	}
	return nil
}
