package dockerauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type jwtPayload struct {
	Iss    string    `json:"iss"`
	Aud    string    `json:"aud"`
	Sub    string    `json:"sub"`
	Nbf    int64     `json:"nbf"`
	Exp    int64     `json:"exp"`
	Iat    int64     `json:"iat"`
	Jti    string    `json:"jti"`
	Access []*access `json:"access"`
}

func generateToken(username string, accessClaims []*access) (string, error) {
	key, err := getPrivateKey()
	if err != nil {
		return "", err
	}

	now := time.Now()

	header := &jwtHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: getRSAKeyID(key),
	}

	payload := &jwtPayload{
		Iss:    config.Registry.Auth.Issuer,
		Aud:    config.Registry.Name,
		Sub:    username,
		Nbf:    now.Add(-30 * time.Second).Unix(),
		Exp:    now.Add(time.Hour).Unix(),
		Iat:    now.Unix(),
		Access: accessClaims,
	}

	uuid, err := generateUUID()
	if err != nil {
		return "", err
	}
	payload.Jti = uuid

	headerEncoded := jsonEncodeJWTSection(header)
	payloadEncoded := jsonEncodeJWTSection(payload)
	signature, err := signJWT(headerEncoded, payloadEncoded, key)
	if err != nil {
		return "", err
	}
	signature = base64Encode(signature)

	return fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signature), nil
}

func jsonEncodeJWTSection(i interface{}) []byte {
	JSON, _ := json.Marshal(i)
	return base64Encode(JSON)
}

func base64Encode(src []byte) []byte {
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(src)))
	base64.RawURLEncoding.Encode(encoded, src)
	return encoded
}

func signJWT(header, payload []byte, key *rsa.PrivateKey) ([]byte, error) {
	hasher := crypto.SHA256.New()
	message := append(header, '.')
	message = append(message, payload...)
	hasher.Write(message)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hasher.Sum(nil))
	return sigBytes, err
}
