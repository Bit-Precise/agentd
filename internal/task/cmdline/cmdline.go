// Package cmdline parses an exec_command `cmd` into simple commands without a
// shell (design 5.6): only literal words, pipes, &&, || and ; are accepted.
package cmdline

import (
	"errors"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Pipeline is a list of commands connected by |.
type Pipeline [][]string

// Chain is pipelines joined by && / || (Ops[i] sits between Pipelines[i] and [i+1]).
type Chain struct {
	Pipelines []Pipeline
	Ops       []string
}

// Script is chains run one after another (separated by ; or newlines).
type Script []Chain

// Commands lists every argv in the script, in order.
func (s Script) Commands() [][]string {
	var out [][]string
	for _, c := range s {
		for _, p := range c.Pipelines {
			out = append(out, p...)
		}
	}
	return out
}

// Parse parses cmd, rejecting any syntax a plain exec cannot honour.
func Parse(cmd string) (Script, error) {
	if strings.TrimSpace(cmd) == "" {
		return nil, errors.New("empty command")
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	var script Script
	for _, st := range f.Stmts {
		var chain Chain
		if err := chainOf(st, &chain); err != nil {
			return nil, err
		}
		script = append(script, chain)
	}
	if len(script) == 0 {
		return nil, errors.New("empty command")
	}
	return script, nil
}

func checkStmt(st *syntax.Stmt) error {
	switch {
	case st.Background, st.Coprocess:
		return errors.New("background jobs are not supported")
	case st.Negated:
		return errors.New("negation (!) is not supported")
	case len(st.Redirs) > 0:
		return errors.New("redirections are not supported")
	}
	return nil
}

func chainOf(st *syntax.Stmt, c *Chain) error {
	if err := checkStmt(st); err != nil {
		return err
	}
	if b, ok := st.Cmd.(*syntax.BinaryCmd); ok && (b.Op == syntax.AndStmt || b.Op == syntax.OrStmt) {
		if err := chainOf(b.X, c); err != nil {
			return err
		}
		c.Ops = append(c.Ops, map[syntax.BinCmdOperator]string{syntax.AndStmt: "&&", syntax.OrStmt: "||"}[b.Op])
		p, err := pipelineOf(b.Y)
		if err != nil {
			return err
		}
		c.Pipelines = append(c.Pipelines, p)
		return nil
	}
	p, err := pipelineOf(st)
	if err != nil {
		return err
	}
	c.Pipelines = append(c.Pipelines, p)
	return nil
}

func pipelineOf(st *syntax.Stmt) (Pipeline, error) {
	if err := checkStmt(st); err != nil {
		return nil, err
	}
	switch cmd := st.Cmd.(type) {
	case *syntax.BinaryCmd:
		if cmd.Op != syntax.Pipe {
			if cmd.Op == syntax.PipeAll {
				return nil, errors.New("|& is not supported")
			}
			return nil, errors.New("&& and || cannot appear inside a pipeline")
		}
		left, err := pipelineOf(cmd.X)
		if err != nil {
			return nil, err
		}
		right, err := pipelineOf(cmd.Y)
		if err != nil {
			return nil, err
		}
		return append(left, right...), nil
	case *syntax.CallExpr:
		if len(cmd.Assigns) > 0 {
			return nil, errors.New("variable assignments are not supported")
		}
		if len(cmd.Args) == 0 {
			return nil, errors.New("empty command")
		}
		argv := make([]string, 0, len(cmd.Args))
		for _, w := range cmd.Args {
			s, err := literal(w)
			if err != nil {
				return nil, err
			}
			argv = append(argv, s)
		}
		return Pipeline{argv}, nil
	case nil:
		return nil, errors.New("empty command")
	default:
		return nil, fmt.Errorf("%T is not supported; only simple commands, |, &&, || and ; are", cmd)
	}
}

func literal(w *syntax.Word) (string, error) {
	var b strings.Builder
	for i, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			v := p.Value
			if i == 0 && strings.HasPrefix(v, "~") {
				return "", errors.New("tilde expansion is not supported")
			}
			s, err := unescape(v, false)
			if err != nil {
				return "", err
			}
			b.WriteString(s)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", errors.New("$'...' quoting is not supported")
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return "", errors.New(`$"..." quoting is not supported`)
			}
			for _, q := range p.Parts {
				lit, ok := q.(*syntax.Lit)
				if !ok {
					return "", errors.New("expansions inside double quotes are not supported")
				}
				s, err := unescape(lit.Value, true)
				if err != nil {
					return "", err
				}
				b.WriteString(s)
			}
		default:
			return "", fmt.Errorf("%T (expansion or substitution) is not supported", part)
		}
	}
	return b.String(), nil
}

// unescape removes shell backslash escapes. Unquoted globbing and brace
// characters are rejected because a shell would expand them.
func unescape(v string, quoted bool) (string, error) {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '\\' && i+1 < len(v) {
			n := v[i+1]
			if !quoted || strings.IndexByte("\"\\$`\n", n) >= 0 {
				if n != '\n' {
					b.WriteByte(n)
				}
				i++
				continue
			}
			b.WriteByte(c)
			continue
		}
		if !quoted && strings.IndexByte("*?[]{}", c) >= 0 {
			return "", fmt.Errorf("unquoted %q (globbing or brace expansion) is not supported", c)
		}
		b.WriteByte(c)
	}
	return b.String(), nil
}
