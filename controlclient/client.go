// Package controlclient implements agent enrollment, desired-config updates and
// effective-config polling against Control.
package controlclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bit-precise/agentd/api"
	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/credentials"
)

type Client struct {
	cfg  *config.Config
	http *http.Client
}

// HTTPError keeps only Control's bounded error kind and message, never the raw
// body. Control writes these messages itself and never includes secrets.
type HTTPError struct {
	StatusCode int
	Kind       string
	Message    string
}

func (e *HTTPError) Error() string {
	if e.Kind == "" {
		return fmt.Sprintf("control rejected request (HTTP %d)", e.StatusCode)
	}
	return fmt.Sprintf("control rejected request (HTTP %d %s): %s", e.StatusCode, e.Kind, e.Message)
}

// AuthenticationRejected means the device credential is revoked, expired or
// unknown. Retrying cannot help; the profile must be enrolled again.
func AuthenticationRejected(err error) bool {
	var e *HTTPError
	return errors.As(err, &e) && e.StatusCode == http.StatusUnauthorized
}

// Rejected means Control refused the request content: invalid configuration
// (400), a policy or role violation (403) or a name/version conflict (409).
// Retrying the same request cannot succeed.
func Rejected(err error) bool {
	var e *HTTPError
	return errors.As(err, &e) && (e.StatusCode == http.StatusBadRequest || e.StatusCode == http.StatusForbidden || e.StatusCode == http.StatusConflict)
}

func boundedText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > limit {
		s = s[:limit]
	}
	return s
}

func New(cfg *config.Config) (*Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.Transport.CAFile != "" {
		data, err := os.ReadFile(cfg.Transport.CAFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, errors.New("invalid control CA")
		}
		tc.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSClientConfig = tc
	return &Client{cfg: cfg, http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("control redirects are forbidden") }}}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) request(ctx context.Context, method, path, token string, body, out any) error {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.cfg.Instance, "/")+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return fmt.Errorf("control request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (2<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 2<<20 {
		return errors.New("control response exceeds limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		failure := &HTTPError{StatusCode: resp.StatusCode}
		var body struct {
			Error struct {
				Kind    string `json:"kind"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &body) == nil {
			failure.Kind, failure.Message = boundedText(body.Error.Kind, 32), boundedText(body.Error.Message, 256)
		}
		return failure
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("invalid control response")
	}
	return nil
}
func (c *Client) Enroll(ctx context.Context, key string) (api.EnrollResponse, error) {
	var response api.EnrollResponse
	request := api.EnrollRequest{EnrollmentKey: key, Instance: c.cfg.Instance, Endpoint: c.cfg.Transport.Endpoint, Workspace: c.cfg.Workspace, Name: c.cfg.Agent.Name, Desired: c.cfg.AgentSpec()}
	err := c.request(ctx, "POST", "/api/v1/enroll", "", request, &response)
	if err == nil {
		err = c.validate(response.Credentials)
		response.Credentials.ControlURL = c.cfg.Instance
	}
	return response, err
}
func (c *Client) validate(v credentials.Credentials) error {
	if v.Version != api.CredentialsVersion || v.AgentID == "" || v.Workspace != c.cfg.Workspace {
		return errors.New("control response identity mismatch")
	}
	if v.ControlURL != "" && strings.TrimSuffix(v.ControlURL, "/") != strings.TrimSuffix(c.cfg.Instance, "/") {
		return errors.New("control response origin mismatch")
	}
	if err := v.Effective.Validate(); err != nil {
		return err
	}
	if !v.Effective.ExpiresAt.After(time.Now()) {
		return errors.New("control returned an expired effective configuration")
	}
	return nil
}
func (c *Client) Refresh(ctx context.Context, current credentials.Credentials) (credentials.Credentials, error) {
	var next credentials.Credentials
	if current.ControlToken == "" {
		return next, errors.New("no control credential")
	}
	if strings.TrimSuffix(current.ControlURL, "/") != strings.TrimSuffix(c.cfg.Instance, "/") {
		return next, errors.New("stored control credential belongs to a different instance")
	}
	if err := c.request(ctx, "GET", "/api/v1/agent/credentials", current.ControlToken, nil, &next); err != nil {
		return next, err
	}
	if err := c.validate(next); err != nil {
		return next, err
	}
	if next.AgentID != current.AgentID || next.Effective.Revision < current.Effective.Revision {
		return next, errors.New("stale or mismatched effective configuration")
	}
	next.ControlToken = current.ControlToken
	next.ControlURL = c.cfg.Instance
	if next.ProviderToken == "" {
		next.ProviderToken = current.ProviderToken
	}
	if next.AccessToken == "" {
		next.AccessToken = current.AccessToken
	}
	return next, nil
}

// Update submits the desired spec of cfg. Control validates it automatically
// and either applies it, returning the Agent with its new effective
// configuration, or rejects it (see Rejected) while the previous one remains.
func (c *Client) Update(ctx context.Context, current credentials.Credentials, cfg *config.Config) (api.Agent, error) {
	var agent api.Agent
	if strings.TrimSuffix(current.ControlURL, "/") != strings.TrimSuffix(c.cfg.Instance, "/") {
		return agent, errors.New("stored control credential belongs to a different instance")
	}
	update := api.ConfigUpdate{Workspace: cfg.Workspace, Name: cfg.Agent.Name, Desired: cfg.AgentSpec()}
	err := c.request(ctx, "POST", "/api/v1/agent/config", current.ControlToken, update, &agent)
	return agent, err
}
