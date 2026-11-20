package goSet

import (
	"crypto/sha256"
	"encoding/hex"
)

// copyJtiDomain separates DeriveCopyJti hashes from any other use of SHA-256
// over the same strings.
const copyJtiDomain = "i2gosignals/copy-jti/v1"

// DeriveCopyJti returns the wire jti of the re-signed copy of inboundJti sent
// on targetStreamID. It is deterministic: the same pair always yields the
// same value. The result is a canonical lowercase 36-character UUID string,
// version nibble 8 (RFC 9562), variant 10.
func DeriveCopyJti(targetStreamID string, inboundJti string) string {
	h := sha256.Sum256([]byte(copyJtiDomain + "\x00" + targetStreamID + "\x00" + inboundJti))
	var u [16]byte
	copy(u[:], h[0:16])
	if in, ok := parseCanonicalUUID(inboundJti); ok {
		if v := in[6] >> 4; v == 7 || v == 8 {
			copy(u[0:8], in[0:8])
		}
	}
	u[6] = (u[6] & 0x0f) | 0x80
	u[8] = (u[8] & 0x3f) | 0x80
	return formatUUID(u)
}

// parseCanonicalUUID parses a 36-character 8-4-4-4-12 hex UUID string (either
// case). It reports false for any other form.
func parseCanonicalUUID(s string) ([16]byte, bool) {
	var u [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return u, false
	}
	hexOnly := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err := hex.Decode(u[:], []byte(hexOnly)); err != nil {
		return u, false
	}
	return u, true
}

func formatUUID(u [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], u[10:16])
	return string(buf[:])
}
