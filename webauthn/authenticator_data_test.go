package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"slices"
	"testing"
)

func TestParseRegistrationPublicKey(t *testing.T) {
	authData, err := parseNoneAttestation(registrationAttestationFixture)
	if err != nil {
		t.Fatal(err)
	}
	withExtensions := append(slices.Clone(authData), 0xa0)
	withExtensions[32] |= 0x80
	for _, tt := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"valid", authData, true},
		{"valid with extensions", withExtensions, true},
		{"missing extension map", withExtensions[:len(authData)], false},
		{"trailing data without ED", append(slices.Clone(authData), 0xa0), false},
		{"truncated credential metadata", authData[:54], false},
		{"truncated credential ID", authData[:57], false},
		{"truncated COSE key", authData[:len(authData)-1], false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseRegistrationPublicKey(tt.data, []byte{1, 2, 3})
			if !tt.valid {
				if err == nil {
					t.Fatal("expected invalid authenticator data to be rejected")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			curve := elliptic.P256()
			if key.Curve != curve || key.X.Cmp(curve.Params().Gx) != 0 || key.Y.Cmp(curve.Params().Gy) != 0 {
				t.Fatal("decoded key differs from the fixture public key")
			}
		})
	}
}

func TestParseES256PublicKey(t *testing.T) {
	params := elliptic.P256().Params()
	for _, tt := range []struct {
		name  string
		label int
		value any
		valid bool
	}{
		{"wrong key type", 1, uint64(1), false},
		{"wrong algorithm", 3, int64(-8), false},
		{"wrong curve", -1, uint64(2), false},
		{"short x coordinate", -2, []byte{1}, false},
		{"short y coordinate", -3, []byte{1}, false},
		{"point outside curve", -3, make([]byte, 32), false},
		{"compressed point", -3, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			values := map[int]any{
				1: uint64(2), 3: int64(-7), -1: uint64(1),
				-2: params.Gx.FillBytes(make([]byte, 32)),
				-3: params.Gy.FillBytes(make([]byte, 32)),
			}
			values[tt.label] = tt.value
			key, err := parseES256PublicKey(values)
			if (err == nil) != tt.valid {
				t.Fatalf("parseES256PublicKey() error = %v, valid = %t", err, tt.valid)
			}
			if tt.valid && (key.X.Cmp(params.Gx) != 0 || key.Y.Cmp(params.Gy) != 0) {
				t.Fatal("decoded point differs from the fixture")
			}
		})
	}
}

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
		{"backup state without eligibility", "localhost", 0x55, 37, false},
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
