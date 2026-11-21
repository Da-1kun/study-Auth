package main

import (
	"encoding/json"
	"reflect"
	"testing"
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
				Header:  map[string]json.RawMessage{"alg": json.RawMessage(`"RS256"`)},
				Payload: map[string]json.RawMessage{"sub": json.RawMessage(`"123"`)},
			},
		},
		{name: "missing segment", token: header + "." + payload, wantErr: true},
		{name: "invalid base64url", token: "!" + "." + payload + ".c2ln", wantErr: true},
		{name: "invalid JSON", token: header + ".ew.c2ln", wantErr: true},
		{name: "payload is not an object", token: header + ".bnVsbA.c2ln", wantErr: true},
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
