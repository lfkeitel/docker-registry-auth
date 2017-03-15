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
*/

import (
	"os"
	"reflect"
	"sort"
	"testing"
)

func check(got []string, expected []string) bool {
	sort.Strings(got)
	sort.Strings(expected)
	return reflect.DeepEqual(expected, got)
}

type testZGlob struct {
	pattern  string
	expected []string
	err      error
}

var testGlobs = []testZGlob{
	{`fo*`, []string{`foo`}, nil},
	{`foo`, []string{`foo`}, nil},
	{`foo/*`, []string{`foo/bar`, `foo/baz`}, nil},
	{`foo/**`, []string{`foo/bar`, `foo/baz`}, nil},
	{`f*o/**`, []string{`foo/bar`, `foo/baz`}, nil},
	{`*oo/**`, []string{`foo/bar`, `foo/baz`, `hoo/bar`}, nil},
	{`*oo/b*`, []string{`foo/bar`, `foo/baz`, `hoo/bar`}, nil},
	{`*oo/*z`, []string{`foo/baz`}, nil},
	{`foo/**/*`, []string{`foo/bar`, `foo/bar/baz`, `foo/bar/baz.txt`, `foo/bar/baz/noo.txt`, `foo/baz`}, nil},
	{`*oo/**/*`, []string{`foo/bar`, `foo/bar/baz`, `foo/bar/baz.txt`, `foo/bar/baz/noo.txt`, `foo/baz`, `hoo/bar`}, nil},
	{`*oo/*.txt`, []string{}, nil},
	{`*oo/*/*.txt`, []string{`foo/bar/baz.txt`}, nil},
	{`*oo/**/*.txt`, []string{`foo/bar/baz.txt`, `foo/bar/baz/noo.txt`}, nil},
	{`doo`, nil, os.ErrNotExist},
	{`./f*`, []string{`foo`}, nil},
}

func TestMatch(t *testing.T) {
	for _, test := range testGlobs {
		for _, f := range test.expected {
			got := globMatch(test.pattern, f)
			if !got {
				t.Errorf("%q should match with %q", f, test.pattern)
			}
		}
	}
}

var extraGlobTests = []struct {
	pattern, str string
	expected     bool
}{
	{
		pattern:  "*",
		str:      "alpine",
		expected: true,
	},
	{
		pattern:  "*",
		str:      "alpine/something",
		expected: false,
	},
	{
		pattern:  "**",
		str:      "alpine/something",
		expected: true,
	},
	{
		pattern:  "level1/*",
		str:      "level1/something",
		expected: true,
	},
	{
		pattern:  "level1/*",
		str:      "level1/something/another",
		expected: false,
	},
	{
		pattern:  "level1/something",
		str:      "level1/something",
		expected: true,
	},
	{
		pattern:  "level1/something",
		str:      "level1/something1",
		expected: false,
	},
	{
		pattern:  "level1/*/another",
		str:      "level1/something/another",
		expected: true,
	},
	{
		pattern:  "level1/**",
		str:      "level1/something/another",
		expected: true,
	},
	{
		pattern:  "level1/**/another",
		str:      "level1/something/other/another",
		expected: true,
	},
	{
		pattern:  "*",
		str:      "127.0.0.1",
		expected: true,
	},
	{
		pattern:  "127.*",
		str:      "127.0.0.1",
		expected: true,
	},
	{
		pattern:  "127.*",
		str:      "128.0.0.1",
		expected: false,
	},
	{
		pattern:  "128.*",
		str:      "127.0.0.1",
		expected: false,
	},
	{
		pattern:  "127.0.10.*",
		str:      "127.0.0.1",
		expected: false,
	},
	{
		pattern:  "127.0.10.*",
		str:      "127.0.10.5",
		expected: true,
	},
}

func TestExtraMatchs(t *testing.T) {
	for _, test := range extraGlobTests {
		check := globMatch(test.pattern, test.str)
		assert(t, check == test.expected,
			"globMatch error. Pattern %s, test %s. Got %t, expected %t",
			test.pattern, test.str, check, test.expected)
	}
}
