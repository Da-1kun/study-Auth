package main

import (
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestVerifyNoneAttestation(t *testing.T) {
	tests := []struct {
		name   string
		format any
		stmt   any
		auth   any
		valid  bool
	}{
		{"none with empty map", "none", map[string]any{}, []byte{1}, true},
		{"different format", "packed", map[string]any{}, []byte{1}, false},
		{"nonempty statement", "none", map[string]any{"sig": []byte{1}}, []byte{1}, false},
		{"null statement", "none", nil, []byte{1}, false},
		{"array statement", "none", []any{}, []byte{1}, false},
		{"array authData", "none", map[string]any{}, []int{1}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := cbor.Marshal(map[string]any{
				"fmt": tt.format, "attStmt": tt.stmt, "authData": tt.auth,
			})
			if err != nil {
				t.Fatal(err)
			}
			err = verifyNoneAttestation(base64.RawURLEncoding.EncodeToString(data))
			if (err == nil) != tt.valid {
				t.Errorf("verifyNoneAttestation() error = %v, valid = %t", err, tt.valid)
			}
		})
	}
}
