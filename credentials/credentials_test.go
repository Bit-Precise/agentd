package credentials

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validCredentials() Credentials {
	return Credentials{
		Version: 1, Workspace: "w1", AgentID: "agent-123", ProviderToken: "provider-secret",
		Approval: Approval{Revision: 7, ExpiresAt: time.Now().Add(time.Hour), Services: map[string]string{"demo": "http://127.0.0.1:8080"}},
	}
}

func writeCredentials(t *testing.T, dir string, value any, mode os.FileMode) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, Filename)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadProvisionedCredentials(t *testing.T) {
	for _, tokenRole := range []string{"provider", "access", "both"} {
		t.Run(tokenRole, func(t *testing.T) {
			dir := privateTempDir(t)
			want := validCredentials()
			if tokenRole != "provider" {
				want.AccessToken = "access-secret"
			}
			if tokenRole == "access" {
				want.ProviderToken = ""
			}
			writeCredentials(t, dir, want, 0600)
			got, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got.AgentID != want.AgentID || got.ProviderToken != want.ProviderToken || got.AccessToken != want.AccessToken || got.Approval.Revision != 7 {
				t.Fatal("loaded credentials differ from the provisioned identity")
			}
		})
	}
}

func TestRejectInvalidCredentialsAndExpiredApprovals(t *testing.T) {
	for name, modify := range map[string]func(*Credentials){
		"wrong version":  func(c *Credentials) { c.Version = 2 },
		"no workspace":   func(c *Credentials) { c.Workspace = "" },
		"no agent ID":    func(c *Credentials) { c.AgentID = "" },
		"no token":       func(c *Credentials) { c.ProviderToken = "" },
		"no revision":    func(c *Credentials) { c.Approval.Revision = 0 },
		"missing expiry": func(c *Credentials) { c.Approval.ExpiresAt = time.Time{} },
		"expired":        func(c *Credentials) { c.Approval.ExpiresAt = time.Now().Add(-time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			dir := privateTempDir(t)
			c := validCredentials()
			modify(&c)
			writeCredentials(t, dir, c, 0600)
			if _, err := Load(dir); err == nil {
				t.Fatal("accepted invalid identity or approval")
			}
		})
	}
}

func TestCredentialsFileType(t *testing.T) {
	t.Run("symlink", func(t *testing.T) {
		target := writeCredentials(t, privateTempDir(t), validCredentials(), 0600)
		dir := privateTempDir(t)
		credentialSymlink(t, target, filepath.Join(dir, Filename))
		if _, err := Load(dir); err == nil {
			t.Fatal("accepted symlinked credentials")
		}
	})
	t.Run("directory", func(t *testing.T) {
		dir := privateTempDir(t)
		if err := os.Mkdir(filepath.Join(dir, Filename), 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(dir); err == nil {
			t.Fatal("accepted nonregular credential file")
		}
	})
}

func TestCredentialsStrictJSONAndSizeLimit(t *testing.T) {
	good, err := json.Marshal(validCredentials())
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"unknown field":        append([]byte(`{"secretTypo":"must-not-leak",`), good[1:]...),
		"duplicate root key":   append([]byte(`{"version":2,`), good[1:]...),
		"duplicate nested key": []byte(strings.Replace(string(good), `"revision":7`, `"revision":6,"revision":7`, 1)),
		"second object":        append(append([]byte{}, good...), []byte("\n{}")...),
		"trailing garbage":     append(append([]byte{}, good...), []byte("garbage")...),
		"invalid secret":       []byte(`{"providerToken":"must-not-leak", invalid}`),
		"oversize":             []byte(strings.Repeat(" ", (1<<20)+1)),
		"empty":                nil,
	} {
		t.Run(name, func(t *testing.T) {
			dir := privateTempDir(t)
			if err := os.WriteFile(filepath.Join(dir, Filename), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(dir); err == nil {
				t.Fatal("accepted invalid credentials JSON")
			} else if strings.Contains(err.Error(), "must-not-leak") {
				t.Fatal("credential parsing exposed secret input")
			}
		})
	}
}

func TestPrivateFileCloseReleasesPlatformHandlesOnce(t *testing.T) {
	dir := privateTempDir(t)
	path := writeCredentials(t, dir, validCredentials(), 0600)
	f, err := openPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	previousRelease := f.release
	calls := 0
	f.release = func() {
		calls++
		if previousRelease != nil {
			previousRelease()
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("platform handles released %d times", calls)
	}
}
