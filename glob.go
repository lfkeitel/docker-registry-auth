package dockerauth

/*
Source: https://github.com/mattn/go-zglob

Copyright (c) mattn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

Original code by mattn. Modifications for this application made by Lee Keitel.
*/

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var (
	envre = regexp.MustCompile(`^(\$[a-zA-Z][a-zA-Z0-9_]+|\$\([a-zA-Z][a-zA-Z0-9_]+\))$`)
)

type zenv struct {
	fre  *regexp.Regexp
	root string
}

func makePattern(pattern string) *zenv {
	globmask := ""
	root := ""
	for _, i := range strings.Split(filepath.ToSlash(pattern), "/") {
		if root == "" && strings.Index(i, "*") != -1 {
			if globmask == "" {
				root = "."
			} else {
				root = filepath.ToSlash(globmask)
			}
		}
		if envre.MatchString(i) {
			i = strings.Trim(strings.Trim(os.Getenv(i[1:]), "()"), `"`)
		}

		globmask = filepath.Join(globmask, i)
	}
	if root == "" {
		return &zenv{
			fre:  nil,
			root: "",
		}
	}
	if globmask == "" {
		globmask = "."
	}
	globmask = filepath.ToSlash(filepath.Clean(globmask))

	cc := []rune(globmask)
	filemask := ""
	for i := 0; i < len(cc); i++ {
		if cc[i] == '*' {
			if i <= len(cc)-2 && cc[i+1] == '*' {
				filemask += "(.*)?"
				i += 2
			} else {
				filemask += "[^/]*"
			}
		} else {
			c := cc[i]
			if c == '/' || ('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || 255 < c {
				filemask += string(c)
			} else {
				filemask += fmt.Sprintf("[\\x%02X]", c)
			}
		}
	}
	if len(filemask) > 0 && filemask[len(filemask)-1] == '/' {
		if root == "" {
			root = filemask
		}
		filemask += "[^/]*"
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		filemask = "(?i:" + filemask + ")"
	}
	return &zenv{
		fre:  regexp.MustCompile("^" + filemask + "$"),
		root: filepath.Clean(root),
	}
}

func globMatch(pattern, name string) bool {
	// ** by itself matches everything
	if pattern == "**" {
		return true
	}

	zenv := makePattern(pattern)
	if zenv.root == "" {
		return pattern == name
	}

	name = filepath.ToSlash(name)

	if name == "." || len(name) <= len(zenv.root) {
		return false
	}

	return zenv.fre.MatchString(name)
}
