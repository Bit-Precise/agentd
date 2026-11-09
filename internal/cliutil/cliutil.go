// Package cliutil holds small helpers shared by the three command-line tools.
package cliutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"gopkg.in/yaml.v3"
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

// ReadDoc reads a YAML or JSON file ("-" is standard input) and returns it as
// JSON, so it can be decoded into generated API types.
func ReadDoc(path string) ([]byte, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	return YAMLToJSON(b)
}

// YAMLToJSON converts a YAML (or JSON) document to JSON.
func YAMLToJSON(b []byte) ([]byte, error) {
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// Column selects a value from a JSON object by dotted path.
type Column struct {
	Header string
	Path   string
}

// Table prints JSON (an array of objects, or one object) as aligned columns.
func Table(w io.Writer, body []byte, cols []Column) error {
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		var one map[string]any
		if err2 := json.Unmarshal(body, &one); err2 != nil {
			return err
		}
		rows = []map[string]any{one}
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	var hs []string
	for _, c := range cols {
		hs = append(hs, c.Header)
	}
	fmt.Fprintln(tw, strings.Join(hs, "\t"))
	for _, r := range rows {
		var vs []string
		for _, c := range cols {
			vs = append(vs, format(lookup(r, c.Path)))
		}
		fmt.Fprintln(tw, strings.Join(vs, "\t"))
	}
	return tw.Flush()
}

// KV prints an object as "key: value" lines (nested values as JSON).
func KV(w io.Writer, body []byte) error {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s: %s\n", k, format(m[k]))
	}
	return nil
}

// PrettyJSON prints JSON indented.
func PrettyJSON(w io.Writer, body []byte) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, body, "", "  "); err != nil {
		_, err = w.Write(body)
		return err
	}
	buf.WriteByte('\n')
	_, err := buf.WriteTo(w)
	return err
}

func lookup(m map[string]any, path string) any {
	var cur any = m
	for _, p := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[p]
	}
	return cur
}

func format(v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case string:
		if t, err := time.Parse(time.RFC3339Nano, x); err == nil {
			return t.Local().Format("2006-01-02 15:04")
		}
		if x == "" {
			return "-"
		}
		return x
	case bool:
		if x {
			return "yes"
		}
		return "no"
	case float64:
		return fmt.Sprintf("%g", x)
	case []any:
		var parts []string
		for _, e := range x {
			parts = append(parts, format(e))
		}
		if len(parts) == 0 {
			return "-"
		}
		return strings.Join(parts, ",")
	case map[string]any:
		if k, ok := x["kind"]; ok {
			if val, ok := x["value"]; ok {
				return fmt.Sprintf("%v:%v", k, val)
			}
		}
		b, _ := json.Marshal(x)
		return string(b)
	}
	return fmt.Sprint(v)
}

// APIResponse is implemented by every generated client response.
type APIResponse interface{ StatusCode() int }

// Check returns the body of a successful response or the API error.
func Check[T APIResponse](r T, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	v := reflect.ValueOf(r)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil, errors.New("no response")
	}
	body := v.Elem().FieldByName("Body").Bytes()
	if s := r.StatusCode(); s/100 != 2 {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error.Code != "" {
			return nil, fmt.Errorf("%s: %s", e.Error.Code, e.Error.Message)
		}
		return nil, fmt.Errorf("HTTP %d: %s", s, strings.TrimSpace(string(body)))
	}
	return body, nil
}
