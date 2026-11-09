//go:build linux || darwin

package elevator

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// run executes a configuration command and returns its output.
func run(name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// runIn feeds stdin to a command (scutil).
func runIn(stdin, name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}
