package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	auth "github.com/lfkeitel/docker-registry-auth"
)

var (
	addr string
)

func init() {
	flag.StringVar(&addr, "addr", ":8080", "Network address to use")
}

func main() {
	flag.Parse()

	if err := auth.LoadConfig(flag.Args()[0]); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	http.HandleFunc("/api/auth", authHandler)
	http.ListenAndServe(addr, nil)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Request: %s\n", r.URL.String())
	if err := auth.ProcessRequest(w, r); err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}
