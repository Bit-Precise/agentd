package cmdline

import (
	"reflect"
	"testing"
)

func TestParseAccepted(t *testing.T) {
	cases := []struct {
		in   string
		want Script
	}{
		{"lark-cli msg send --to ops --text hi", Script{{Pipelines: []Pipeline{{{"lark-cli", "msg", "send", "--to", "ops", "--text", "hi"}}}}}},
		{`echo "a b" 'c d' e\ f`, Script{{Pipelines: []Pipeline{{{"echo", "a b", "c d", "e f"}}}}}},
		{"git status && git log -1 || true", Script{{Pipelines: []Pipeline{{{"git", "status"}}, {{"git", "log", "-1"}}, {{"true"}}}, Ops: []string{"&&", "||"}}}},
		{"ls -la | head -5 | wc -l", Script{{Pipelines: []Pipeline{{{"ls", "-la"}, {"head", "-5"}, {"wc", "-l"}}}}}},
		{"date; uname -a\nwhoami", Script{
			{Pipelines: []Pipeline{{{"date"}}}},
			{Pipelines: []Pipeline{{{"uname", "-a"}}}},
			{Pipelines: []Pipeline{{{"whoami"}}}},
		}},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parse(%q) = %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestParseRejected(t *testing.T) {
	for _, in := range []string{
		"echo $HOME",
		"echo $(id)",
		"echo `id`",
		"ls > out",
		"cat < /etc/passwd",
		"ls *",
		"ls ~/x",
		"FOO=1 ls",
		"(ls)",
		"{ ls; }",
		"ls &",
		"! ls",
		"if true; then ls; fi",
		"echo {a,b}",
		"echo $'x'",
		"",
		"   ",
	} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}

func TestCommands(t *testing.T) {
	s, err := Parse("a 1 | b 2 && c 3; d")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"a", "1"}, {"b", "2"}, {"c", "3"}, {"d"}}
	if got := s.Commands(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Commands = %v", got)
	}
}
