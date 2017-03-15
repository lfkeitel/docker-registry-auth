package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

var (
	ErrInvalidLogin   = errors.New("Invalid username or password")
	ErrInvalidScope   = errors.New("Invalid scope format")
	ErrUnknownService = errors.New("Unknown service")
)

func GetBasicCredentials(r *http.Request) (string, string) {
	header := r.Header.Get(http.CanonicalHeaderKey("Authorization"))
	if header == "" {
		return "", ""
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}

	if parts[0] != "Basic" {
		return "", ""
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}

	parts = strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", ""
	}

	username, _ := url.QueryUnescape(parts[0])
	password, _ := url.QueryUnescape(parts[1])
	return username, password
}

func ProcessRequest(w http.ResponseWriter, r *http.Request) error {
	username, password := GetBasicCredentials(r)
	token, err := GetToken(username, password, r.URL.Query().Get("service"), r.URL.Query().Get("scope"))
	if err != nil {
		return err
	}
	fmt.Printf("Token: %s\n", token)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"token": "%s"}`, token)))
	return nil
}

func GetToken(username, password, service, scope string) (string, error) {
	var acc []*access
	if service != config.Registry.Name {
		return "", ErrUnknownService
	}

	if scope != "" {
		req := parseScope(scope)
		if req == nil {
			return "", ErrInvalidScope
		}

		ok, err := authenticate(username, password)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrInvalidLogin
		}

		acls, err := getACLS(username)
		if err != nil {
			return "", err
		}

		acc = []*access{compareACLS(acls, req)}
	} else {
		acc = make([]*access, 0)
	}

	token, err := generateToken(username, acc)
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func authenticate(username, password string) (bool, error) {
	return true, nil
}

func getACLS(username string) ([]*accessControl, error) {
	return nil, nil
}

func compareACLS(acls []*accessControl, req *access) *access {
	return req
}
