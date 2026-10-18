// Package controlclient implements agent enrollment and approved-config polling.
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

	types "github.com/bit-precise/agentd/api"
	"github.com/bit-precise/agentd/config"
	"github.com/bit-precise/agentd/credentials"
)

type Client struct {
	cfg  *config.Config
	http *http.Client
}

// HTTPError deliberately omits the response body: it can contain private data.
type HTTPError struct{ StatusCode int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("control rejected request (HTTP %d)", e.StatusCode)
}
func AuthenticationRejected(err error) bool {
	var e *HTTPError
	return errors.As(err, &e) && (e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden)
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
		return &HTTPError{StatusCode: resp.StatusCode}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return errors.New("invalid control response")
	}
	return nil
}
func (c *Client) Enroll(ctx context.Context, key string) (types.EnrollResponse, error) {
	var response types.EnrollResponse
	err := c.request(ctx, "POST", "/api/v1/enroll", "", types.EnrollRequest{EnrollmentKey: key, Config: *c.cfg}, &response)
	if err == nil {
		err = c.validate(response.Credentials)
		response.Credentials.ControlURL = c.cfg.Instance
	}
	return response, err
}
func (c *Client) validate(v credentials.Credentials) error {
	if v.Version != 1 || v.AgentID == "" || v.Workspace != c.cfg.Workspace || v.Approval.Revision == 0 {
		return errors.New("control response identity mismatch")
	}
	if v.ControlURL != "" && strings.TrimSuffix(v.ControlURL, "/") != strings.TrimSuffix(c.cfg.Instance, "/") {
		return errors.New("control response origin mismatch")
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
	if next.AgentID != current.AgentID || next.Approval.Revision < current.Approval.Revision {
		return next, errors.New("stale or mismatched control approval")
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
func (c *Client) Update(ctx context.Context, current credentials.Credentials, cfg *config.Config) error {
	if strings.TrimSuffix(current.ControlURL, "/") != strings.TrimSuffix(c.cfg.Instance, "/") {
		return errors.New("stored control credential belongs to a different instance")
	}
	return c.request(ctx, "POST", "/api/v1/agent/config", current.ControlToken, cfg, nil)
}
