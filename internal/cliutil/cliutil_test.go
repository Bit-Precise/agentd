package cliutil

import (
	"flag"
	"reflect"
	"testing"
)

func TestParseInterleaved(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	w := fs.String("w", "", "")
	pos, err := ParseInterleaved(fs, []string{"exec", "-w", "home", "office", "--", "uname", "-s", "--", "x"})
	if err != nil || *w != "home" || !reflect.DeepEqual(pos, []string{"exec", "office", "uname", "-s", "--", "x"}) {
		t.Fatalf("pos=%v w=%q err=%v", pos, *w, err)
	}
}
