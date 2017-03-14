package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/naoina/toml"
)

var (
	config  *Config
	privKey *rsa.PrivateKey
)

type Config struct {
	Registry *RegistryConfig
	User     []*UserConfig
}

type RegistryConfig struct {
	Address     string
	Name        string
	AllowDelete bool
	Auth        struct {
		Enabled bool
		Key     string
		Issuer  string
	}
}

type UserConfig struct {
	Username    string
	Password    string
	Hash        string
	Permissions []*UserPermissionConfig
}

type UserPermissionConfig struct {
	IP         string
	Repository string
	Access     []string
}

func LoadConfig(path string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			switch x := r.(type) {
			case string:
				err = errors.New(x)
			case error:
				err = x
			default:
				err = errors.New("Unknown panic")
			}
		}
	}()

	if path == "" {
		path = "config.toml"
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	var con Config
	if err := toml.Unmarshal(buf, &con); err != nil {
		return err
	}
	config = &con
	fmt.Printf("%#v\n", config)

	return nil
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	if privKey != nil {
		return privKey, nil
	}

	bytes, err := ioutil.ReadFile(config.Registry.Auth.Key)
	if err != nil {
		return nil, err
	}

	rsaPrivate, err := crypto.ParseRSAPrivateKeyFromPEM(bytes)
	if err != nil {
		return nil, err
	}

	privKey = rsaPrivate
	return privKey
}
