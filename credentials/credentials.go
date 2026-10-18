// Package credentials manages provisioned agent identities and the last synced
// effective configuration in the private profile directory.
package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bit-precise/agentd/api"
	"github.com/bit-precise/agentd/policy"
)

const Filename = "credentials.json"

// privateFile pins checked Windows parent directories during credential reads.
type privateFile struct {
	*os.File
	release   func()
	closeOnce sync.Once
	closeErr  error
}

func (f *privateFile) Close() error {
	f.closeOnce.Do(func() {
		f.closeErr = f.File.Close()
		if f.release != nil {
			f.release()
		}
	})
	return f.closeErr
}

// Credentials are provisioned by the control plane or an operator, never
// inferred from config.yaml. Without a control token the effective snapshot is
// fixed and stops authorizing flows at its expiry.
type Credentials = api.Credentials

// legacyCredentials is version 1 from the removed manual-approval model. It is
// converted on load; the next control refresh replaces the converted snapshot.
type legacyCredentials struct {
	Version       int    `json:"version"`
	Workspace     string `json:"workspace"`
	AgentID       string `json:"agentId"`
	ProviderToken string `json:"providerToken,omitempty"`
	AccessToken   string `json:"accessToken,omitempty"`
	ControlToken  string `json:"controlToken,omitempty"`
	ControlURL    string `json:"controlUrl,omitempty"`
	Approval      struct {
		Revision  uint64            `json:"revision"`
		ExpiresAt time.Time         `json:"expiresAt"`
		Services  map[string]string `json:"services,omitempty"`
		Egress    []policy.Rule     `json:"egress,omitempty"`
		Deny      []policy.Rule     `json:"deny,omitempty"`
	} `json:"approval"`
}

func (l legacyCredentials) convert() Credentials {
	c := Credentials{Version: api.CredentialsVersion, Workspace: l.Workspace, AgentID: l.AgentID, ProviderToken: l.ProviderToken,
		AccessToken: l.AccessToken, ControlToken: l.ControlToken, ControlURL: l.ControlURL,
		Effective: api.EffectiveConfig{Revision: l.Approval.Revision, ExpiresAt: l.Approval.ExpiresAt, Ingress: l.AccessToken != "", Egress: l.Approval.Egress, Deny: l.Approval.Deny}}
	for name, origin := range l.Approval.Services {
		c.Effective.Services = append(c.Effective.Services, api.EffectiveService{Name: name, Origin: origin})
	}
	slices.SortFunc(c.Effective.Services, func(a, b api.EffectiveService) int { return strings.Compare(a.Name, b.Name) })
	return c
}

func Load(stateDir string) (*Credentials, error) {
	path := filepath.Join(stateDir, Filename)
	f, err := openPrivate(path)
	if err != nil {
		return nil, fmt.Errorf("load provisioned credentials: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat credentials: %w", err)
	}
	if err := validatePrivateFile(info); err != nil {
		return nil, err
	}
	if info.Size() > 1<<20 {
		return nil, errors.New("credentials file exceeds 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	if len(data) > 1<<20 {
		return nil, errors.New("credentials file exceeds 1 MiB")
	}
	if err := uniqueJSON(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return nil, errors.New("invalid or ambiguous credentials JSON")
	}
	var probe struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, errors.New("invalid credentials JSON")
	}
	var c Credentials
	switch probe.Version {
	case api.CredentialsVersion:
		err = decodeStrict(data, &c)
	case 1:
		var legacy legacyCredentials
		if err = decodeStrict(data, &legacy); err == nil {
			c = legacy.convert()
		}
	default:
		return nil, errors.New("credentials require version 2 (or legacy version 1)")
	}
	if err != nil {
		return nil, err
	}
	if c.Workspace == "" || c.AgentID == "" {
		return nil, errors.New("credentials require workspace and agentId")
	}
	if c.ProviderToken == "" && c.AccessToken == "" && c.ControlToken == "" {
		return nil, errors.New("credentials contain no session token")
	}
	if err := c.Effective.Validate(); err != nil {
		return nil, err
	}
	if !c.Effective.ExpiresAt.After(time.Now()) && (c.ControlToken == "" || c.ControlURL == "") {
		return nil, errors.New("effective configuration snapshot is expired and cannot be refreshed")
	}
	return &c, nil
}

func decodeStrict(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return errors.New("invalid credentials JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("credentials must contain one JSON object")
	}
	return nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting limit")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	opening, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch opening {
	case '{':
		keys := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			name = strings.ToLower(name)
			if !ok || keys[name] {
				return errors.New("duplicate JSON key")
			}
			keys[name] = true
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected delimiter")
	}
	_, err = d.Token()
	return err
}
