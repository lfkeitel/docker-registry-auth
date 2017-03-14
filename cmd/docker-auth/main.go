package main

import (
	"fmt"
	"os"

	auth "github.com/lfkeitel/docker-registry-auth"
)

func main() {
	if err := auth.LoadConfig(os.Args[1]); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}
