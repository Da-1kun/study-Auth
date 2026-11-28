package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	signCountOffset             = sha256.Size + 1 // RP ID hash と flags の直後
	authenticatorDataHeaderSize = signCountOffset + 4

	flagUserPresent            = 1 << 0
	flagUserVerified           = 1 << 2
	flagBackupEligible         = 1 << 3
	flagBackupState            = 1 << 4
	flagAttestedCredentialData = 1 << 6
	flagExtensionData          = 1 << 7
)

func authenticatorSignCount(authData []byte) uint32 {
	return binary.BigEndian.Uint32(authData[signCountOffset:authenticatorDataHeaderSize])
}

func verifyRegistrationAuthenticatorData(authData []byte) error {
	const requiredFlags = flagUserPresent | flagUserVerified | flagAttestedCredentialData
	return verifyAuthenticatorDataHeader(authData, requiredFlags)
}

func verifyLoginAuthenticatorData(authData []byte, backupEligible bool) error {
	if err := verifyAuthenticatorDataHeader(authData, flagUserPresent|flagUserVerified); err != nil {
		return err
	}
	flags := authData[sha256.Size]
	if flags&flagAttestedCredentialData != 0 {
		return errors.New("unexpected attested credential data in assertion")
	}
	if (flags&flagBackupEligible != 0) != backupEligible {
		return errors.New("credential backup eligibility mismatch")
	}
	return verifyAuthenticatorExtensions(authData[authenticatorDataHeaderSize:], flags)
}

func verifyAuthenticatorDataHeader(authData []byte, requiredFlags byte) error {
	if len(authData) < authenticatorDataHeaderSize {
		return errors.New("authData header is too short")
	}

	expectedRPIDHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(authData[:sha256.Size], expectedRPIDHash[:]) {
		return errors.New("authData RP ID hash mismatch")
	}

	flags := authData[sha256.Size]
	if flags&requiredFlags != requiredFlags {
		return errors.New("authData is missing required flags")
	}
	if flags&flagBackupState != 0 && flags&flagBackupEligible == 0 {
		return errors.New("authData sets BS without BE")
	}
	return nil
}

// parseRegistrationPublicKey は、ヘッダー検証済みの authData から公開鍵を取り出す。
func parseRegistrationPublicKey(authData, rawID []byte) (*ecdsa.PublicKey, error) {
	const credentialIDOffset = authenticatorDataHeaderSize + 16 + 2 // AAGUID と credential ID の長さ
	if len(authData) < credentialIDOffset {
		return nil, errors.New("truncated attested credential data")
	}
	idLength := int(binary.BigEndian.Uint16(authData[credentialIDOffset-2 : credentialIDOffset]))
	if idLength == 0 || idLength > len(authData)-credentialIDOffset {
		return nil, errors.New("invalid credential ID length")
	}
	keyOffset := credentialIDOffset + idLength
	if !bytes.Equal(authData[credentialIDOffset:keyOffset], rawID) {
		return nil, errors.New("credential ID does not match rawId")
	}

	var key map[int]any
	rest, err := attestationDecoder.UnmarshalFirst(authData[keyOffset:], &key)
	if err != nil {
		return nil, errors.New("invalid credential public key CBOR")
	}
	if err := verifyAuthenticatorExtensions(rest, authData[sha256.Size]); err != nil {
		return nil, err
	}
	return parseES256PublicKey(key)
}

func verifyAuthenticatorExtensions(rest []byte, flags byte) error {
	if flags&flagExtensionData != 0 {
		var extensions map[string]any
		if err := attestationDecoder.Unmarshal(rest, &extensions); err != nil || extensions == nil {
			return errors.New("invalid authenticator extensions")
		}
	} else if len(rest) != 0 {
		return errors.New("unexpected trailing authenticator data")
	}
	return nil
}

func parseES256PublicKey(key map[int]any) (*ecdsa.PublicKey, error) {
	const (
		keyTypeLabel   = 1
		algorithmLabel = 3
		curveLabel     = -1
		xLabel         = -2
		yLabel         = -3
		coordinateSize = 32
	)
	if len(key) != 5 || key[keyTypeLabel] != uint64(2) || key[algorithmLabel] != int64(es256Algorithm) ||
		key[curveLabel] != uint64(1) {
		return nil, errors.New("credential public key must be an EC2 P-256 ES256 key")
	}

	x, ok := key[xLabel].([]byte)
	if !ok || len(x) != coordinateSize {
		return nil, errors.New("invalid credential public key x coordinate")
	}

	curve := elliptic.P256()
	switch y := key[yLabel].(type) {
	case []byte:
		if len(y) != coordinateSize {
			return nil, errors.New("invalid credential public key y coordinate")
		}
		var point [1 + 2*coordinateSize]byte
		point[0] = 0x04 // SEC 1 の非圧縮形式
		copy(point[1:], x)
		copy(point[1+coordinateSize:], y)
		return ecdsa.ParseUncompressedPublicKey(curve, point[:])
	case bool:
		var point [1 + coordinateSize]byte
		point[0] = 0x02 // SEC 1 の圧縮形式（y が偶数）
		if y {
			point[0] = 0x03 // y が奇数
		}
		copy(point[1:], x)
		pointX, pointY := elliptic.UnmarshalCompressed(curve, point[:])
		if pointX != nil {
			return &ecdsa.PublicKey{Curve: curve, X: pointX, Y: pointY}, nil
		}
	}
	return nil, errors.New("invalid credential public key point")
}
