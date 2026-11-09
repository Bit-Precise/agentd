package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"agentd/internal/adminapi"
	"agentd/internal/cliutil"
)

type cmdCtx struct {
	*client
	fs    *flag.FlagSet
	args  []string
	ctx   context.Context
	strs  map[string]*string
	bools map[string]*bool
	multi map[string]*multi
}

func (c *cmdCtx) defStr(name, def, usage string) {
	if c.strs == nil {
		c.strs = map[string]*string{}
	}
	c.strs[name] = c.fs.String(name, def, usage)
}
func (c *cmdCtx) defBool(name, usage string) {
	if c.bools == nil {
		c.bools = map[string]*bool{}
	}
	c.bools[name] = c.fs.Bool(name, false, usage)
}
func (c *cmdCtx) defMulti(name, usage string) {
	if c.multi == nil {
		c.multi = map[string]*multi{}
	}
	m := &multi{}
	c.fs.Var(m, name, usage)
	c.multi[name] = m
}
func (c *cmdCtx) s(name string) string   { return *c.strs[name] }
func (c *cmdCtx) b(name string) bool     { return *c.bools[name] }
func (c *cmdCtx) m(name string) []string { return *c.multi[name] }
func (c *cmdCtx) set(name string) bool {
	found := false
	c.fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// admin dispatches "<noun> <verb> [args]" to the admin API.
func admin(args []string) error {
	noun, verb := args[0], ""
	rest := args[1:]
	if noun != "status" && noun != "apply" {
		if len(rest) == 0 {
			return fmt.Errorf("usage: agentserver %s <command>; see agentserver help", noun)
		}
		verb, rest = rest[0], rest[1:]
	}
	if noun == "relay" && verb == "token" {
		if len(rest) == 0 {
			return errors.New("usage: agentserver relay token list|create|revoke")
		}
		noun, verb, rest = "relay-token", rest[0], rest[1:]
	}
	fs := flag.NewFlagSet(noun+" "+verb, flag.ExitOnError)
	server := fs.String("server", cliutil.Env("AGENTSERVER_ADMIN_URL", "http://127.0.0.1:7800"), "admin API base URL")
	token := fs.String("token", os.Getenv("AGENTSERVER_ADMIN_TOKEN"), "admin token")
	out := fs.String("o", "table", "output: table or json")
	ws := fs.String("w", os.Getenv("AGENTSERVER_WORKSPACE"), "workspace")
	fs.StringVar(ws, "workspace", os.Getenv("AGENTSERVER_WORKSPACE"), "workspace")
	h, ok := commands[noun+" "+verb]
	if !ok {
		return fmt.Errorf("unknown command %q; see agentserver help", strings.TrimSpace(noun+" "+verb))
	}
	c := &cmdCtx{fs: fs, ctx: context.Background()}
	h.flags(c)
	pos, err := cliutil.ParseInterleaved(fs, rest)
	if err != nil {
		return err
	}
	if c.client, err = newClient(*server, *token, *out, *ws); err != nil {
		return err
	}
	if h.needWS && c.ws == "" {
		return errors.New("this command needs -w <workspace> (or AGENTSERVER_WORKSPACE)")
	}
	if len(pos) < h.minArgs {
		return fmt.Errorf("usage: agentserver %s %s %s", strings.ReplaceAll(noun, "-", " "), verb, h.usage)
	}
	c.args = pos
	return h.run(c)
}

type command struct {
	usage   string
	minArgs int
	needWS  bool
	flags   func(*cmdCtx)
	run     func(*cmdCtx) error
}

func noFlags(*cmdCtx) {}

type result struct {
	body []byte
	err  error
}

func chk[T cliutil.APIResponse](r T, err error) result {
	b, err := cliutil.Check(r, err)
	return result{b, err}
}

// show prints a successful response as a table or JSON.
func (c *cmdCtx) show(r result, cols ...cliutil.Column) error {
	body, err := r.body, r.err
	if err != nil {
		return err
	}
	if c.out == "json" || len(body) == 0 {
		if len(body) == 0 {
			return nil
		}
		return cliutil.PrettyJSON(os.Stdout, body)
	}
	if len(cols) == 0 {
		return cliutil.KV(os.Stdout, body)
	}
	return cliutil.Table(os.Stdout, body, cols)
}

func (c *cmdCtx) done(r result, msg string) error {
	body, err := r.body, r.err
	if err != nil {
		return err
	}
	if c.out == "json" && len(body) > 0 {
		return cliutil.PrettyJSON(os.Stdout, body)
	}
	fmt.Println(msg)
	return nil
}

func col(h, p string) cliutil.Column { return cliutil.Column{Header: h, Path: p} }

var (
	wsCols      = []cliutil.Column{col("NAME", "name"), col("BASE DOMAIN", "base_domain"), col("RELAY", "relay"), col("MEMBERS", "members"), col("ONLINE", "members_online"), col("CERT", "cert.state")}
	relayCols   = []cliutil.Column{col("NAME", "name"), col("URL", "url"), col("CONNECTED", "connected"), col("NODES", "nodes_online"), col("WORKSPACES", "workspaces"), col("PUBLIC KEY", "public_key")}
	tokenCols   = []cliutil.Column{col("ID", "id"), col("NAME", "name"), col("ROLES", "roles"), col("EXPIRES", "expires_at")}
	nodeCols    = []cliutil.Column{col("NAME", "name"), col("ONLINE", "online"), col("ROLES", "role_caps"), col("SERVICES", "services"), col("LAST SEEN", "last_seen"), col("PUBLIC KEY", "public_key")}
	groupCols   = []cliutil.Column{col("NAME", "name"), col("MEMBERS", "members"), col("PUBLIC KEY", "public_key")}
	routeCols   = []cliutil.Column{col("ID", "id"), col("FROM", "from"), col("PROTO", "proto"), col("DOMAINS", "domains"), col("TO", "to")}
	policyCols  = []cliutil.Column{col("ID", "id"), col("SUBJECTS", "subjects"), col("ALLOW", "allow"), col("DENY", "deny"), col("COMMENT", "comment")}
	serviceCols = []cliutil.Column{col("NAME", "name"), col("FQDN", "fqdn"), col("PROTO", "proto"), col("NODE", "node"), col("STATE", "state"), col("PUBLIC", "public")}
	certCols    = []cliutil.Column{col("DOMAIN", "domain"), col("STATE", "state"), col("ISSUER", "issuer"), col("NOT AFTER", "not_after"), col("ERROR", "last_error")}
	rtokCols    = []cliutil.Column{col("ID", "id"), col("CREATED", "created_at"), col("EXPIRES", "expires_at")}
)

func roles(s string) *[]adminapi.Role {
	if s == "" {
		return nil
	}
	var rs []adminapi.Role
	for _, r := range strings.Split(s, ",") {
		rs = append(rs, adminapi.Role(strings.TrimSpace(r)))
	}
	return &rs
}

func strp(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// parseMatch reads "suffix:example.com" or "domain:a.example.com" (bare
// values are suffixes).
func parseMatch(s string) adminapi.Match {
	kind, val, ok := strings.Cut(s, ":")
	if !ok {
		return adminapi.Match{Kind: "suffix", Value: s}
	}
	return adminapi.Match{Kind: adminapi.MatchKind(kind), Value: val}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func readInto(path string, v any) error {
	if path == "" {
		return errors.New("-f <file> is required (YAML or JSON, - for stdin)")
	}
	b, err := cliutil.ReadDoc(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
