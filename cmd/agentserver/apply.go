package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"agentd/internal/adminapi"
	"agentd/internal/cliutil"
)

// workspaceDoc is the `kind: Workspace` file (design 9.1).
type workspaceDoc struct {
	APIVersion  string                           `json:"apiVersion"`
	Kind        string                           `json:"kind"`
	Name        string                           `json:"name"`
	BaseDomain  string                           `json:"base_domain"`
	DNSProvider string                           `json:"dns_provider"`
	Relay       string                           `json:"relay"`
	PublishDNS  *bool                            `json:"publish_dns"`
	Routes      *[]adminapi.RouteWrite           `json:"routes"`
	Default     string                           `json:"default"`
	Groups      map[string][]string              `json:"groups"`
	Policies    *[]adminapi.PolicyStatementWrite `json:"policies"`
}

// apply converges a workspace to a Workspace file: creates or updates it,
// replaces routes and policies when given, and syncs group membership.
func apply(c *cmdCtx) error {
	b, err := cliutil.ReadDoc(c.s("f"))
	if err != nil {
		return err
	}
	var d workspaceDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}
	if d.APIVersion != "agentd/v1" || d.Kind != "Workspace" {
		return fmt.Errorf("expected apiVersion agentd/v1 and kind Workspace, got %q %q", d.APIVersion, d.Kind)
	}
	if d.Name == "" || d.Relay == "" {
		return errors.New("a Workspace needs name and relay")
	}
	cur, err := c.api.GetWorkspaceWithResponse(c.ctx, d.Name)
	if err != nil {
		return err
	}
	switch cur.StatusCode() {
	case http.StatusNotFound:
		if _, err := cliutil.Check(c.api.CreateWorkspaceWithResponse(c.ctx, adminapi.WorkspaceCreate{Name: d.Name, Relay: d.Relay,
			BaseDomain: strp(d.BaseDomain), DnsProvider: strp(d.DNSProvider), PublishDns: d.PublishDNS})); err != nil {
			return err
		}
		fmt.Printf("workspace %s created\n", d.Name)
	case http.StatusOK:
		w := cur.JSON200
		if d.BaseDomain != "" && d.BaseDomain != w.BaseDomain {
			return fmt.Errorf("base_domain cannot change (%s → %s); create a new workspace", w.BaseDomain, d.BaseDomain)
		}
		p := adminapi.WorkspacePatch{}
		changed := false
		if w.Relay != d.Relay {
			p.Relay, changed = &d.Relay, true
		}
		if d.PublishDNS != nil && (w.PublishDns == nil || *w.PublishDns != *d.PublishDNS) {
			p.PublishDns, changed = d.PublishDNS, true
		}
		if d.DNSProvider != "" && (w.DnsProvider == nil || *w.DnsProvider != d.DNSProvider) {
			p.DnsProvider, changed = &d.DNSProvider, true
		}
		if changed {
			if _, err := cliutil.Check(c.api.UpdateWorkspaceWithResponse(c.ctx, d.Name, p)); err != nil {
				return err
			}
			fmt.Printf("workspace %s updated\n", d.Name)
		}
	default:
		if _, err := cliutil.Check(cur, nil); err != nil {
			return err
		}
	}

	if d.Routes != nil || d.Default != "" {
		t := adminapi.RouteTableWrite{Routes: []adminapi.RouteWrite{}}
		if d.Routes != nil {
			t.Routes = *d.Routes
		}
		if d.Default != "" {
			def := adminapi.RouteTableWriteDefault(d.Default)
			t.Default = &def
		}
		if _, err := cliutil.Check(c.api.ReplaceRouteTableWithResponse(c.ctx, d.Name, t)); err != nil {
			return fmt.Errorf("routes: %w", err)
		}
		fmt.Printf("routes replaced (%d)\n", len(t.Routes))
	}

	if len(d.Groups) > 0 {
		gl, err := c.api.ListGroupsWithResponse(c.ctx, d.Name)
		if _, err := cliutil.Check(gl, err); err != nil {
			return err
		}
		have := map[string]map[string]bool{}
		for _, g := range *gl.JSON200 {
			m := map[string]bool{}
			for _, n := range g.Members {
				m[n] = true
			}
			have[g.Name] = m
		}
		for name, members := range d.Groups {
			cur, ok := have[name]
			if !ok {
				empty := []string{}
				if _, err := cliutil.Check(c.api.CreateGroupWithResponse(c.ctx, d.Name, adminapi.GroupCreate{Name: name, Members: &empty})); err != nil {
					return fmt.Errorf("group %s: %w", name, err)
				}
				cur = map[string]bool{}
				fmt.Printf("group %s created\n", name)
			}
			want := map[string]bool{}
			for _, n := range members {
				want[n] = true
				if !cur[n] {
					if _, err := cliutil.Check(c.api.AddGroupMemberWithResponse(c.ctx, d.Name, name, n)); err != nil {
						fmt.Printf("group %s: skip %s: %v\n", name, n, err)
					}
				}
			}
			for n := range cur {
				if !want[n] {
					if _, err := cliutil.Check(c.api.RemoveGroupMemberWithResponse(c.ctx, d.Name, name, n)); err != nil {
						return fmt.Errorf("group %s: remove %s: %w", name, n, err)
					}
				}
			}
		}
	}

	if d.Policies != nil {
		if _, err := cliutil.Check(c.api.ReplacePoliciesWithResponse(c.ctx, d.Name, *d.Policies)); err != nil {
			return fmt.Errorf("policies: %w", err)
		}
		fmt.Printf("policies replaced (%d)\n", len(*d.Policies))
	}
	return nil
}
