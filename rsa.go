package auth

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"
)

var (
	privKey *rsa.PrivateKey
	keyID   string

	ErrKeyMustBePEMEncoded = errors.New("invalid key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	ErrNotRSAPrivateKey    = errors.New("key is not a valid RSA private key")
)

func getPrivateKey() (*rsa.PrivateKey, error) {
	if privKey != nil {
		return privKey, nil
	}

	bytes, err := ioutil.ReadFile(config.Registry.Auth.Key)
	if err != nil {
		return nil, err
	}

	rsaPrivate, err := parseRSAPrivateKeyFromPEM(bytes)
	if err != nil {
		return nil, err
	}

	privKey = rsaPrivate
	return privKey, nil
}

// parseRSAPrivateKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 private key.
func parseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, ErrNotRSAPrivateKey
	}

	return pkey, nil
}

func getRSAKeyID(key *rsa.PrivateKey) string {
	if keyID == "" { // Only generate the key if needed
		derBytes, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return ""
		}
		hasher := crypto.SHA256.New()
		hasher.Write(derBytes)

		s := strings.TrimRight(base32.StdEncoding.EncodeToString(hasher.Sum(nil)[:30]), "=")
		var buf bytes.Buffer
		var i int
		for i = 0; i < len(s)/4-1; i++ {
			start := i * 4
			end := start + 4
			buf.WriteString(s[start:end] + ":")
		}
		buf.WriteString(s[i*4:])
		keyID = buf.String()
	}
	return keyID
}
