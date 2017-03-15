package auth

import (
	"crypto/rand"
	"encoding/hex"
)

func generateUUID() (string, error) {
	var u [16]byte

	// Generate random bytes
	if _, err := rand.Read(u[:]); err != nil {
		return "", err
	}

	// Set version
	u[6] = (u[6] & 0x0f) | (4 << 4)

	// Set variant
	u[8] = (u[8] & 0xbf) | 0x80

	return uuidToString(u), nil
}

func uuidToString(u [16]byte) string {
	buf := make([]byte, 36)

	hex.Encode(buf[0:8], u[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], u[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], u[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], u[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:], u[10:])

	return string(buf)
}
