package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// CloudflareClient is the minimal Cloudflare DNS API client used for ACME
// DNS-01 challenges and publish_dns.
type CloudflareClient struct {
	Token   string
	BaseURL string // default https://api.cloudflare.com/client/v4
	HTTP    *http.Client
}

// DNSRecord is a Cloudflare DNS record.
type DNSRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl,omitempty"`
	Proxied *bool  `json:"proxied,omitempty"`
}

type cfEnvelope struct {
	Success bool                       `json:"success"`
	Errors  []struct{ Message string } `json:"errors"`
	Result  json.RawMessage            `json:"result"`
}

func (c *CloudflareClient) do(ctx context.Context, method, path string, body, out any) error {
	base := c.BaseURL
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env cfEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("cloudflare %s %s: %s: %w", method, path, resp.Status, err)
	}
	if !env.Success {
		msgs := []string{}
		for _, e := range env.Errors {
			msgs = append(msgs, e.Message)
		}
		return fmt.Errorf("cloudflare %s %s: %s", method, path, strings.Join(msgs, "; "))
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// ZoneFor finds the zone containing name by trying ever shorter suffixes.
func (c *CloudflareClient) ZoneFor(ctx context.Context, name string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 0; i < len(labels)-1; i++ {
		zone := strings.Join(labels[i:], ".")
		var zones []struct {
			ID string `json:"id"`
		}
		if err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(zone), nil, &zones); err != nil {
			return "", err
		}
		if len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("no cloudflare zone contains %s", name)
}

// CreateRecord creates a record and returns its id.
func (c *CloudflareClient) CreateRecord(ctx context.Context, zone string, r DNSRecord) (string, error) {
	var out DNSRecord
	if err := c.do(ctx, http.MethodPost, "/zones/"+zone+"/dns_records", r, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

// DeleteRecord deletes a record.
func (c *CloudflareClient) DeleteRecord(ctx context.Context, zone, id string) error {
	return c.do(ctx, http.MethodDelete, "/zones/"+zone+"/dns_records/"+id, nil, nil)
}

// UpsertRecord creates or updates the record with the same type and name.
func (c *CloudflareClient) UpsertRecord(ctx context.Context, zone string, r DNSRecord) error {
	var existing []DNSRecord
	q := "/zones/" + zone + "/dns_records?type=" + url.QueryEscape(r.Type) + "&name=" + url.QueryEscape(r.Name)
	if err := c.do(ctx, http.MethodGet, q, nil, &existing); err != nil {
		return err
	}
	if len(existing) > 0 {
		return c.do(ctx, http.MethodPut, "/zones/"+zone+"/dns_records/"+existing[0].ID, r, nil)
	}
	_, err := c.CreateRecord(ctx, zone, r)
	return err
}
