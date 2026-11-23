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

func verifyNoneAttestation(encoded string) error {
	data, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return errors.New("invalid attestationObject encoding")
	}
	var object map[string]any
	if err := attestationDecoder.Unmarshal(data, &object); err != nil {
		return errors.New("invalid attestationObject CBOR")
	}
	if format, ok := object["fmt"].(string); !ok || format != "none" {
		return errors.New("attestation format must be none")
	}
	if statement, ok := object["attStmt"].(map[any]any); !ok || len(statement) != 0 {
		return errors.New("attStmt must be an empty CBOR map")
	}
	if _, ok := object["authData"].([]byte); !ok {
		return errors.New("authData must be a CBOR byte string")
	}
	return nil
}
