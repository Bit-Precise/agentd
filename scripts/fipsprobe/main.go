// Command fipsprobe checks the exact Go FIPS build mode in release validation.
package main

import (
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	if !fips140.Enabled() {
		fmt.Fprintln(os.Stderr, "FIPS mode is not enabled")
		os.Exit(1)
	}
	var input [32]byte
	if _, err := rand.Read(input[:]); err != nil {
		fmt.Fprintln(os.Stderr, "FIPS random source failed")
		os.Exit(1)
	}
	_ = sha256.Sum256(input[:])
	fmt.Println("Go FIPS module enabled; random and SHA-256 operations succeeded")
}
