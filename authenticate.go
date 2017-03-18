package dockerauth

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

type Logf interface {
	Print(v ...interface{})
	Println(v ...interface{})
	Printf(f string, v ...interface{})

	Error(v ...interface{})
	Errorln(v ...interface{})
	Errorf(f string, v ...interface{})
}

type nullLogger struct{}

func (l *nullLogger) Print(v ...interface{})            {}
func (l *nullLogger) Println(v ...interface{})          {}
func (l *nullLogger) Printf(f string, v ...interface{}) {}
func (l *nullLogger) Error(v ...interface{})            {}
func (l *nullLogger) Errorln(v ...interface{})          {}
func (l *nullLogger) Errorf(f string, v ...interface{}) {}

type UserAuthenticator interface {
	Login(username, password string) (bool, error)
}

type AccessControlStore interface {
	GetACLS(username string) ([]*AccessControl, error)
}

type Authenticator struct {
	userAuthenticator  UserAuthenticator
	accessControlStore AccessControlStore
	log                Logf
}

type Options struct {
	UserAuthenticator  UserAuthenticator
	AccessControlStore AccessControlStore
	Log                Logf
}

func NewAuthenticator(o *Options) *Authenticator {
	if o == nil {
		return nil
	}

	if o.UserAuthenticator == nil {
		return nil
	}

	if o.AccessControlStore == nil {
		return nil
	}

	if o.Log == nil {
		o.Log = &nullLogger{}
	}

	return &Authenticator{
		userAuthenticator:  o.UserAuthenticator,
		accessControlStore: o.AccessControlStore,
		log:                o.Log,
	}
}

func (a *Authenticator) GetBasicCredentials(r *http.Request) (string, string) {
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

func (a *Authenticator) ProcessRequest(w http.ResponseWriter, r *http.Request) error {
	username, password := a.GetBasicCredentials(r)
	token, err := a.GetToken(username, password, r)
	if err != nil {
		return err
	}
	if config.PrintToken {
		a.log.Printf("Granting token: %s\n", token)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"token": "%s"}`, token)))
	return nil
}

func (a *Authenticator) GetToken(username, password string, r *http.Request) (string, error) {
	service := r.URL.Query().Get("service")
	if service != config.Registry.Name {
		return "", ErrUnknownService
	}

	ok, err := a.userAuthenticator.Login(username, password)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrInvalidLogin
	}

	scope := r.URL.Query().Get("scope")

	// No scope, empty access
	if scope == "" {
		return GenerateToken(username, make([]*AccessControl, 0))
	}

	req := parseScope(scope)
	if req == nil {
		return "", ErrInvalidScope
	}

	a.log.Printf("Scope: Type: %s, Name: %s, Actions: %s\n", req.Type, req.Name, strings.Join(req.Actions, ","))

	// No actions asked, return request
	if len(req.Actions) == 0 {
		return GenerateToken(username, []*AccessControl{req})
	}

	acls, err := a.accessControlStore.GetACLS(username)
	if err != nil {
		return "", err
	}

	acls = a.filterRepository(acls, req.Name)

	if !a.checkIPAddress(r, acls) {
		return GenerateToken(username, make([]*AccessControl, 0))
	}

	resp := a.compareACLS(acls, req)

	a.log.Printf("Granting actions: %s\n", strings.Join(resp.Actions, ","))

	return GenerateToken(username, []*AccessControl{resp})
}
