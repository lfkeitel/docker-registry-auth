package auth

import (
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/satori/go.uuid"
)

func GetToken(username, password, service, scope string) (string, error) {
	return "", nil
}

func generateToken(username string, accessClaims []*access) ([]byte, error) {
	key, err := getPrivateKey()
	if err != nil {
		return nil, err
	}

	claims := jws.Claims{}
	claims.SetIssuer(config.Registry.Auth.Issuer)
	claims.SetAudience(config.Registry.Name)
	claims.SetSubject(username)
	claims.SetNotBefore(time.Now().Add(-30 * time.Second))
	claims.SetExpiration(time.Now().Add(6 * time.Hour))
	claims.SetIssuedAt(time.Now())
	claims.SetJWTID(uuid.NewV4().String())
	claims.Set("access", accessClaims)

	jwt := jws.NewJWT(claims, crypto.SigningMethodRS256)

	return jwt.Serialize(key)
}
