// Package cliutil holds small helpers shared by the three command-line tools.
package cliutil

import (
	"flag"
	"fmt"
	"os"
)

// ParseInterleaved parses flags that may appear before, between or after
// positional arguments, returning the positionals.
// Everything after a "--" is positional, verbatim.
func ParseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var tail []string
	for i, a := range args {
		if a == "--" {
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return append(pos, tail...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// Env returns the value of an environment variable or a default.
func Env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// Fatal prints an error and exits.
func Fatal(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
