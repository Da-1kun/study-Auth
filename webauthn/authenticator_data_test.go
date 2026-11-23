package main

import (
	"crypto/sha256"
	"testing"
)

func TestVerifyRegistrationAuthenticatorData(t *testing.T) {
	tests := []struct {
		name  string
		rpID  string
		flags byte
		size  int
		valid bool
	}{
		{"required flags", "localhost", 0x45, 37, true},
		{"additional flags", "localhost", 0x5d, 37, true},
		{"truncated header", "localhost", 0x45, 36, false},
		{"wrong RP ID", "localhost:8081", 0x45, 37, false},
		{"missing UP", "localhost", 0x44, 37, false},
		{"missing UV", "localhost", 0x41, 37, false},
		{"missing AT", "localhost", 0x05, 37, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := sha256.Sum256([]byte(tt.rpID))
			data := make([]byte, tt.size)
			copy(data, hash[:])
			data[32] = tt.flags
			err := verifyRegistrationAuthenticatorData(data)
			if (err == nil) != tt.valid {
				t.Errorf("verifyRegistrationAuthenticatorData() error = %v, valid = %t", err, tt.valid)
			}
		})
	}
}
