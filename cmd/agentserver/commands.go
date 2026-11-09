package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"agentd/internal/adminapi"
	"agentd/internal/cliutil"
)

var commands map[string]command

func init() {
	commands = map[string]command{
		"key show": {run: func(c *cmdCtx) error {
			body, err := cliutil.Check(c.api.GetServerWithResponse(c.ctx))
			if err != nil || c.out == "json" {
				return c.show(result{body, err})
			}
			r, _ := c.api.GetServerWithResponse(c.ctx)
			fmt.Println(r.JSON200.PublicKey)
			return nil
		}, flags: noFlags},
		"status ": {run: func(c *cmdCtx) error {
			return c.show(chk(c.api.GetStatusWithResponse(c.ctx)))
		}, flags: noFlags},
		"apply ": {flags: func(c *cmdCtx) { c.defStr("f", "", "Workspace YAML (kind: Workspace)") }, run: apply},

		// ------------------------------------------------------------ workspaces
		"workspace list": {flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.ListWorkspacesWithResponse(c.ctx)), wsCols...)
		}},
		"workspace get": {usage: "<ws>", minArgs: 1, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.GetWorkspaceWithResponse(c.ctx, c.args[0])))
		}},
		"workspace key": {usage: "<ws>", minArgs: 1, flags: noFlags, run: func(c *cmdCtx) error {
			r, err := c.api.GetWorkspaceWithResponse(c.ctx, c.args[0])
			if _, err := cliutil.Check(r, err); err != nil {
				return err
			}
			fmt.Println(r.JSON200.PublicKey)
			return nil
		}},
		"workspace create": {usage: "<ws> --relay <relay> [--base-domain d] [--dns-provider p] [--publish-dns]", minArgs: 1, flags: func(c *cmdCtx) {
			c.defStr("relay", "", "assigned relay")
			c.defStr("base-domain", "", "base domain (default <ws>.<agentserver domain>)")
			c.defStr("dns-provider", "", "dns provider for the base domain")
			c.defBool("publish-dns", "publish *.<base domain> for public services")
		}, run: func(c *cmdCtx) error {
			if c.s("relay") == "" {
				return errors.New("--relay is required")
			}
			pub := c.b("publish-dns")
			return c.show(chk(c.api.CreateWorkspaceWithResponse(c.ctx, adminapi.WorkspaceCreate{Name: c.args[0], Relay: c.s("relay"),
				BaseDomain: strp(c.s("base-domain")), DnsProvider: strp(c.s("dns-provider")), PublishDns: &pub})))
		}},
		"workspace update": {usage: "<ws> [--relay r] [--dns-provider p] [--publish-dns=true|false]", minArgs: 1, flags: func(c *cmdCtx) {
			c.defStr("relay", "", "assigned relay")
			c.defStr("dns-provider", "", "dns provider")
			c.defBool("publish-dns", "publish *.<base domain>")
		}, run: func(c *cmdCtx) error {
			p := adminapi.WorkspacePatch{Relay: strp(c.s("relay")), DnsProvider: strp(c.s("dns-provider"))}
			if c.set("publish-dns") {
				v := c.b("publish-dns")
				p.PublishDns = &v
			}
			return c.show(chk(c.api.UpdateWorkspaceWithResponse(c.ctx, c.args[0], p)))
		}},
		"workspace set-relay": {usage: "<ws> <relay>", minArgs: 2, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.UpdateWorkspaceWithResponse(c.ctx, c.args[0], adminapi.WorkspacePatch{Relay: &c.args[1]})))
		}},
		"workspace delete": {usage: "<ws> [--force]", minArgs: 1, flags: func(c *cmdCtx) { c.defBool("force", "delete even with members") }, run: func(c *cmdCtx) error {
			f := c.b("force")
			return c.done(chk(c.api.DeleteWorkspaceWithResponse(c.ctx, c.args[0], &adminapi.DeleteWorkspaceParams{Force: &f})), "deleted")
		}},

		// ------------------------------------------------------------ relays
		"relay list": {flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.ListRelaysWithResponse(c.ctx)), relayCols...)
		}},
		"relay get": {usage: "<relay>", minArgs: 1, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.GetRelayWithResponse(c.ctx, c.args[0])))
		}},
		"relay add": {usage: "<relay> --public-key k --url https://… [--stun host:port]", minArgs: 1, flags: func(c *cmdCtx) {
			c.defStr("public-key", "", "relay public key")
			c.defStr("url", "", "relay base URL (https)")
			c.defStr("stun", "", "STUN address")
		}, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.RegisterRelayWithResponse(c.ctx, adminapi.RelayCreate{Name: c.args[0], PublicKey: strings.TrimPrefix(c.s("public-key"), "agentd://"), Url: c.s("url"), Stun: strp(c.s("stun"))})))
		}},
		"relay remove": {usage: "<relay>", minArgs: 1, flags: noFlags, run: func(c *cmdCtx) error {
			return c.done(chk(c.api.RemoveRelayWithResponse(c.ctx, c.args[0])), "removed")
		}},
		"relay certs": {usage: "<relay>", minArgs: 1, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.ListRelayCertsWithResponse(c.ctx, c.args[0])), col("WORKSPACE", "workspace"), col("EXPIRES", "expires_at"))
		}},
		"relay-token list": {flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.ListRelayTokensWithResponse(c.ctx)), rtokCols...)
		}},
		"relay-token create": {flags: func(c *cmdCtx) { c.defStr("ttl", "", "lifetime, e.g. 24h") }, run: func(c *cmdCtx) error {
			r, err := c.api.CreateRelayTokenWithResponse(c.ctx, adminapi.RelayTokenCreate{Ttl: strp(c.s("ttl"))})
			body, err := cliutil.Check(r, err)
			if err != nil || c.out == "json" {
				return c.show(result{body, err})
			}
			fmt.Println(r.JSON201.Token)
			return nil
		}},
		"relay-token revoke": {usage: "<id>", minArgs: 1, flags: noFlags, run: func(c *cmdCtx) error {
			return c.done(chk(c.api.RevokeRelayTokenWithResponse(c.ctx, c.args[0])), "revoked")
		}},

		// ------------------------------------------------------------ join tokens
		"token list": {needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.ListTokensWithResponse(c.ctx, c.ws)), tokenCols...)
		}},
		"token create": {needWS: true, flags: func(c *cmdCtx) {
			c.defStr("name", "", "instance name bound to the token")
			c.defStr("roles", "", "allowed roles, comma separated")
			c.defStr("ttl", "", "lifetime, e.g. 24h")
		}, run: func(c *cmdCtx) error {
			var name *adminapi.Label
			if n := c.s("name"); n != "" {
				name = &n
			}
			r, err := c.api.CreateTokenWithResponse(c.ctx, c.ws, adminapi.TokenCreate{Name: name, Roles: roles(c.s("roles")), Ttl: strp(c.s("ttl"))})
			body, err := cliutil.Check(r, err)
			if err != nil || c.out == "json" {
				return c.show(result{body, err})
			}
			fmt.Println(r.JSON201.JoinLink)
			return nil
		}},
		"token revoke": {usage: "<id>", minArgs: 1, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.done(chk(c.api.RevokeTokenWithResponse(c.ctx, c.ws, c.args[0])), "revoked")
		}},

		// ------------------------------------------------------------ nodes
		"node list": {needWS: true, flags: func(c *cmdCtx) { c.defBool("online", "only online nodes") }, run: func(c *cmdCtx) error {
			var p adminapi.ListNodesParams
			if c.b("online") {
				t := true
				p.Online = &t
			}
			return c.show(chk(c.api.ListNodesWithResponse(c.ctx, c.ws, &p)), nodeCols...)
		}},
		"node get": {usage: "<node>", minArgs: 1, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.GetNodeWithResponse(c.ctx, c.ws, c.args[0])))
		}},
		"node remove": {usage: "<node>", minArgs: 1, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.done(chk(c.api.RemoveNodeWithResponse(c.ctx, c.ws, c.args[0])), "removed")
		}},
		"node rename": {usage: "<node> <new-name>", minArgs: 2, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.UpdateNodeWithResponse(c.ctx, c.ws, c.args[0], adminapi.NodePatch{Name: &c.args[1]})))
		}},
		"node set-roles": {usage: "<node> <role,role…>", minArgs: 2, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.UpdateNodeWithResponse(c.ctx, c.ws, c.args[0], adminapi.NodePatch{RoleCaps: roles(c.args[1])})))
		}},

		// ------------------------------------------------------------ groups
		"group list": {needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.ListGroupsWithResponse(c.ctx, c.ws)), groupCols...)
		}},
		"group get": {usage: "<group>", minArgs: 1, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.GetGroupWithResponse(c.ctx, c.ws, c.args[0])))
		}},
		"group create": {usage: "<group> [member…]", minArgs: 1, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			members := append([]string{}, c.args[1:]...)
			return c.show(chk(c.api.CreateGroupWithResponse(c.ctx, c.ws, adminapi.GroupCreate{Name: c.args[0], Members: &members})))
		}},
		"group delete": {usage: "<group>", minArgs: 1, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.done(chk(c.api.DeleteGroupWithResponse(c.ctx, c.ws, c.args[0])), "deleted")
		}},
		"group add": {usage: "<group> <node>", minArgs: 2, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.done(chk(c.api.AddGroupMemberWithResponse(c.ctx, c.ws, c.args[0], c.args[1])), "added")
		}},
		"group remove": {usage: "<group> <node>", minArgs: 2, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.done(chk(c.api.RemoveGroupMemberWithResponse(c.ctx, c.ws, c.args[0], c.args[1])), "removed")
		}},
	}
	for k, v := range moreCommands() {
		commands[k] = v
	}
}

func moreCommands() map[string]command {
	return map[string]command{
		// ------------------------------------------------------------ routes
		"route list": {needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			r, err := c.api.GetRouteTableWithResponse(c.ctx, c.ws)
			body, err := cliutil.Check(r, err)
			if err != nil || c.out == "json" {
				return c.show(result{body, err})
			}
			fmt.Printf("version %d, default %s\n", r.JSON200.Version, r.JSON200.Default)
			rows, _ := json.Marshal(r.JSON200.Routes)
			return c.show(result{rows, nil}, routeCols...)
		}},
		"route add": {needWS: true, flags: func(c *cmdCtx) {
			c.defStr("from", "workspace", "subject: workspace, node:<n>, group:<g>, agentd://<key>")
			c.defStr("proto", "tls", "protocols, comma separated (tls, ssh)")
			c.defMulti("domain", "domain pattern suffix:<d> or domain:<d> (repeatable)")
			c.defStr("to", "", "egress node, direct or reject")
		}, run: func(c *cmdCtx) error {
			w := adminapi.RouteWrite{From: c.s("from"), To: c.s("to")}
			if w.To == "" || len(c.m("domain")) == 0 {
				return errors.New("--to and at least one --domain are required")
			}
			var ps []adminapi.Proto
			for _, p := range strings.Split(c.s("proto"), ",") {
				ps = append(ps, adminapi.Proto(strings.TrimSpace(p)))
			}
			w.Proto = &ps
			for _, d := range c.m("domain") {
				w.Domains = append(w.Domains, parseMatch(d))
			}
			return c.show(chk(c.api.AddRouteWithResponse(c.ctx, c.ws, w)))
		}},
		"route remove": {usage: "<route-id>", minArgs: 1, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.done(chk(c.api.DeleteRouteWithResponse(c.ctx, c.ws, c.args[0])), "removed")
		}},
		"route replace": {needWS: true, flags: func(c *cmdCtx) { c.defStr("f", "", "file with {routes: [...], default: direct}") }, run: func(c *cmdCtx) error {
			var t adminapi.RouteTableWrite
			if err := readInto(c.s("f"), &t); err != nil {
				return err
			}
			return c.show(chk(c.api.ReplaceRouteTableWithResponse(c.ctx, c.ws, t)))
		}},

		// ------------------------------------------------------------ policies
		"policy list": {needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.ListPoliciesWithResponse(c.ctx, c.ws)), policyCols...)
		}},
		"policy add": {needWS: true, flags: func(c *cmdCtx) { c.defStr("f", "", "file with one statement") }, run: func(c *cmdCtx) error {
			var s adminapi.PolicyStatementWrite
			if err := readInto(c.s("f"), &s); err != nil {
				return err
			}
			return c.show(chk(c.api.AddPolicyWithResponse(c.ctx, c.ws, s)))
		}},
		"policy remove": {usage: "<policy-id>", minArgs: 1, needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.done(chk(c.api.DeletePolicyWithResponse(c.ctx, c.ws, c.args[0])), "removed")
		}},
		"policy replace": {needWS: true, flags: func(c *cmdCtx) { c.defStr("f", "", "file with a list of statements") }, run: func(c *cmdCtx) error {
			var ss []adminapi.PolicyStatementWrite
			if err := readInto(c.s("f"), &ss); err != nil {
				return err
			}
			return c.show(chk(c.api.ReplacePoliciesWithResponse(c.ctx, c.ws, ss)), policyCols...)
		}},

		// ------------------------------------------------------------ services, certs
		"service list": {needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.ListServicesWithResponse(c.ctx, c.ws)), serviceCols...)
		}},
		"cert list": {needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.ListCertsWithResponse(c.ctx, c.ws)), certCols...)
		}},
		"cert renew": {needWS: true, flags: noFlags, run: func(c *cmdCtx) error {
			return c.show(chk(c.api.RenewCertWithResponse(c.ctx, c.ws)))
		}},
	}
}
