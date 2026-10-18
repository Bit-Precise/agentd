// Package deviceflow is a minimal RFC 8628 OAuth 2.0 Device Authorization
// Grant client for a public client. It never logs or persists the device code
// or the access token; callers exchange the token once and discard it.
package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	grantType       = "urn:ietf:params:oauth:grant-type:device_code"
	defaultInterval = 5 * time.Second
	slowDownStep    = 5 * time.Second
	maxBody         = 1 << 20
)

var (
	// ErrDenied means the user declined the authorization in the browser.
	ErrDenied = errors.New("device authorization was denied")
	// ErrExpired means the device code expired or was already used; start again.
	ErrExpired = errors.New("device authorization expired; start a new login")
)

// Endpoints are discovered from the issuer and must share its origin.
type Endpoints struct {
	DeviceAuthorization string
	Token               string
}

// Authorization is the device authorization response. DeviceCode is secret.
type Authorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Token is the issued access token. It is short-lived and single-purpose.
type Token struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	ExpiresIn   int    `json:"expires_in"`
}

type Client struct {
	HTTP *http.Client
	// Sleep waits between polls; tests replace it. It must honor ctx.
	Sleep func(context.Context, time.Duration) error
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// SameOrigin reports whether target is an absolute URL on the issuer's origin.
// Discovery, verification and token endpoints outside it are rejected.
func SameOrigin(issuer, target string) bool {
	i, err := url.Parse(issuer)
	t, terr := url.Parse(target)
	return err == nil && terr == nil && t.IsAbs() && t.User == nil && t.Fragment == "" && strings.EqualFold(i.Scheme, t.Scheme) && strings.EqualFold(i.Host, t.Host)
}

func (c *Client) do(ctx context.Context, method, endpoint string, form url.Values, out any) (int, []byte, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, nil, err
	}
	r.Header.Set("Accept", "application/json")
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.HTTP.Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(data) > maxBody {
		return resp.StatusCode, nil, errors.New("invalid authorization server response")
	}
	if out != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, nil, errors.New("invalid authorization server response")
		}
	}
	return resp.StatusCode, data, nil
}

// Discover reads the issuer's OpenID/OAuth metadata.
func (c *Client) Discover(ctx context.Context, issuer string) (Endpoints, error) {
	var metadata struct {
		Issuer              string `json:"issuer"`
		DeviceAuthorization string `json:"device_authorization_endpoint"`
		Token               string `json:"token_endpoint"`
	}
	status, _, err := c.do(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil, &metadata)
	if err != nil {
		return Endpoints{}, fmt.Errorf("discover authorization server: %w", err)
	}
	if status != http.StatusOK {
		return Endpoints{}, fmt.Errorf("discover authorization server: HTTP %d", status)
	}
	if strings.TrimSuffix(metadata.Issuer, "/") != strings.TrimSuffix(issuer, "/") || !SameOrigin(issuer, metadata.DeviceAuthorization) || !SameOrigin(issuer, metadata.Token) {
		return Endpoints{}, errors.New("authorization server metadata does not match the configured issuer")
	}
	return Endpoints{DeviceAuthorization: metadata.DeviceAuthorization, Token: metadata.Token}, nil
}

// Start requests a device and user code for exactly one scope and audience.
func (c *Client) Start(ctx context.Context, endpoint, clientID, scope, audience string) (Authorization, error) {
	var auth Authorization
	form := url.Values{"client_id": {clientID}, "scope": {scope}}
	if audience != "" {
		form.Set("audience", audience)
	}
	status, data, err := c.do(ctx, http.MethodPost, endpoint, form, &auth)
	if err != nil {
		return auth, fmt.Errorf("start device authorization: %w", err)
	}
	if status != http.StatusOK {
		return auth, fmt.Errorf("start device authorization: %s", oauthError(status, data))
	}
	if auth.DeviceCode == "" || auth.UserCode == "" || auth.VerificationURI == "" || auth.ExpiresIn <= 0 {
		return auth, errors.New("start device authorization: incomplete response")
	}
	return auth, nil
}

func oauthError(status int, data []byte) string {
	var failure struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(data, &failure) == nil && failure.Error != "" {
		return failure.Error
	}
	return fmt.Sprintf("HTTP %d", status)
}

// Poll waits for the user's decision. It polls serially at the server's
// interval, adds five seconds on each slow_down, retries transport failures
// with growing delays, and stops at the device code's expiry.
func (c *Client) Poll(ctx context.Context, endpoint, clientID string, auth Authorization) (Token, error) {
	wait := c.Sleep
	if wait == nil {
		wait = sleep
	}
	interval := time.Duration(auth.Interval) * time.Second
	if interval <= 0 {
		interval = defaultInterval
	}
	deadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	backoff := time.Duration(0)
	form := url.Values{"grant_type": {grantType}, "device_code": {auth.DeviceCode}, "client_id": {clientID}}
	for {
		if err := wait(ctx, interval+backoff); err != nil {
			if errors.Is(err, context.DeadlineExceeded) && !time.Now().Before(deadline) {
				return Token{}, ErrExpired
			}
			return Token{}, err
		}
		var token Token
		status, data, err := c.do(ctx, http.MethodPost, endpoint, form, &token)
		if err != nil || status >= 500 {
			// Network and server failures back off separately; never poll faster.
			backoff = min(max(2*backoff, interval), time.Minute)
			continue
		}
		backoff = 0
		if status == http.StatusOK {
			if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "bearer") {
				return Token{}, errors.New("authorization server returned an unusable token")
			}
			return token, nil
		}
		switch oauthError(status, data) {
		case "authorization_pending":
		case "slow_down":
			interval += slowDownStep
		case "access_denied":
			return Token{}, ErrDenied
		case "expired_token", "invalid_grant":
			return Token{}, ErrExpired
		default:
			return Token{}, fmt.Errorf("device authorization failed: %s", oauthError(status, data))
		}
	}
}
