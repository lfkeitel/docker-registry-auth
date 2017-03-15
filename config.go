package dockerauth

import (
	"errors"
	"io/ioutil"
	"os"

	"github.com/naoina/toml"
)

var (
	config *Config
)

type Config struct {
	PrintToken bool
	Registry   *RegistryConfig
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

type UserAccessConfig struct {
	User []*UserConfig
}

type UserConfig struct {
	Username    string
	Password    string
	Hash        string
	Permissions []*AccessControl
}

func LoadConfig(path string) (err error) {
	c, err := parseConfig(path)
	config = c
	return err
}

func parseConfig(path string) (c *Config, err error) {
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
		return nil, err
	}
	defer f.Close()

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var con Config
	if err := toml.Unmarshal(buf, &con); err != nil {
		return nil, err
	}

	return &con, nil
}

func parseUserConfig(path string) (c *UserAccessConfig, err error) {
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
		return nil, err
	}
	defer f.Close()

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var con UserAccessConfig
	if err := toml.Unmarshal(buf, &con); err != nil {
		return nil, err
	}

	return &con, nil
}
