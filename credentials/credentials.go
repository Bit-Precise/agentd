// Package credentials manages provisioned agent identities and approval snapshots.
package credentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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

// Credentials are provisioned by the operator/control plane, never inferred from
// config.yaml. This first implementation consumes a fixed, expiring snapshot.
type Credentials struct {
	Version       int      `json:"version"`
	Workspace     string   `json:"workspace"`
	AgentID       string   `json:"agentId"`
	ProviderToken string   `json:"providerToken,omitempty"`
	AccessToken   string   `json:"accessToken,omitempty"`
	Approval      Approval `json:"approval"`
}

type Approval struct {
	Revision  uint64            `json:"revision"`
	ExpiresAt time.Time         `json:"expiresAt"`
	Services  map[string]string `json:"services,omitempty"`
	Egress    []policy.Rule     `json:"egress,omitempty"`
	Deny      []policy.Rule     `json:"deny,omitempty"`
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
	var c Credentials
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return nil, errors.New("invalid credentials JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("credentials must contain one JSON object")
	}
	if c.Version != 1 || c.Workspace == "" || c.AgentID == "" {
		return nil, errors.New("credentials require version 1, workspace and agentId")
	}
	if c.ProviderToken == "" && c.AccessToken == "" {
		return nil, errors.New("credentials contain no session token")
	}
	if c.Approval.Revision == 0 || !c.Approval.ExpiresAt.After(time.Now()) {
		return nil, errors.New("approval snapshot is missing or expired")
	}
	for i := range c.Approval.Egress {
		if err := c.Approval.Egress[i].Validate(true); err != nil {
			return nil, errors.New("invalid approved egress rule")
		}
	}
	for i := range c.Approval.Deny {
		if err := c.Approval.Deny[i].Validate(false); err != nil {
			return nil, errors.New("invalid approved deny rule")
		}
	}
	return &c, nil
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
