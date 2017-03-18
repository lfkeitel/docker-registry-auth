package dockerauth

import (
	"errors"
	"fmt"

	passlib "gopkg.in/hlandau/passlib.v1"
)

type FileAuthenticator struct {
	users map[string]*UserConfig
}

func NewFileAuthenticator(filename string) (*FileAuthenticator, error) {
	c, err := parseUserConfig(filename)
	if err != nil {
		return nil, err
	}

	users := make(map[string]*UserConfig)
	for _, u := range c.User {
		users[u.Username] = u
	}

	return &FileAuthenticator{
		users: users,
	}, nil
}

func (a *FileAuthenticator) Login(username, password string) (bool, error) {
	user, exists := a.users[username]
	if !exists {
		return false, nil
	}

	return a.checkPassword(username, password, user.Password, user.Hash), nil
}

func (a *FileAuthenticator) checkPassword(username, password, expected, hash string) bool {
	if hash == "none" {
		fmt.Println("DON'T USE PASSWORD HASH \"none\"")
		return password == expected
	}
	err := passlib.VerifyNoUpgrade(password, expected)
	if err != nil {
		fmt.Println(err)
	}
	return err == nil
}

func (a *FileAuthenticator) GetACLS(username string) ([]*AccessControl, error) {
	u, exists := a.users[username]
	if !exists {
		return nil, errors.New("User doesn't exist")
	}

	return u.Permissions, nil
}
