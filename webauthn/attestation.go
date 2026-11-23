package main

import (
	"encoding/base64"
	"errors"

	"github.com/fxamacker/cbor/v2"
)

var attestationDecoder = func() cbor.DecMode {
	mode, err := (cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
	}).DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

func parseNoneAttestation(encoded string) ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, errors.New("invalid attestationObject encoding")
	}
	var object map[string]any
	if err := attestationDecoder.Unmarshal(data, &object); err != nil {
		return nil, errors.New("invalid attestationObject CBOR")
	}
	if format, ok := object["fmt"].(string); !ok || format != "none" {
		return nil, errors.New("attestation format must be none")
	}
	if statement, ok := object["attStmt"].(map[any]any); !ok || len(statement) != 0 {
		return nil, errors.New("attStmt must be an empty CBOR map")
	}
	authData, ok := object["authData"].([]byte)
	if !ok {
		return nil, errors.New("authData must be a CBOR byte string")
	}
	return authData, nil
}
