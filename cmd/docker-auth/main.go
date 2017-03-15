package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	auth "github.com/lfkeitel/docker-registry-auth"
)

var (
	addr     string
	config   string
	accounts string
)

func init() {
	flag.StringVar(&addr, "addr", ":8080", "Network address to use")
	flag.StringVar(&config, "config", "config.toml", "Configuration file")
	flag.StringVar(&accounts, "accounts", "accounts.toml", "Accounts file")
}

func main() {
	flag.Parse()

	if err := auth.LoadConfig(config); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	http.HandleFunc("/api/auth", authHandlerFactory())
	http.ListenAndServe(addr, nil)
}

func authHandlerFactory() http.HandlerFunc {
	fa, err := auth.NewFileAuthenticator(accounts)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	o := &auth.Options{
		UserAuthenticator:  fa,
		AccessControlStore: fa,
		Log:                &simpleLogger{},
	}

	authenticator := auth.NewAuthenticator(o)
	if authenticator == nil {
		fmt.Println("FIX ME")
		os.Exit(1)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Request: %s\n", r.URL.String())
		if err := authenticator.ProcessRequest(w, r); err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
}

type simpleLogger struct{}

func (l *simpleLogger) Print(v ...interface{}) {
	fmt.Print(v...)
}
func (l *simpleLogger) Println(v ...interface{}) {
	fmt.Println(v...)
}
func (l *simpleLogger) Printf(f string, v ...interface{}) {
	fmt.Printf(f, v...)
}
func (l *simpleLogger) Error(v ...interface{}) {
	fmt.Print("Error: ")
	fmt.Print(v...)
}
func (l *simpleLogger) Errorln(v ...interface{}) {
	fmt.Print("Error: ")
	fmt.Println(v...)
}
func (l *simpleLogger) Errorf(f string, v ...interface{}) {
	fmt.Printf("Error: "+f, v...)
}
