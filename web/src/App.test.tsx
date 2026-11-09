// Renders the console against a fake admin API and walks every resource the
// generator derived from the OpenAPI document.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { App } from "./App";
import { meta } from "./api/meta.gen";

const key = "Rt7aBRt7aBRt7aBRt7aBRt7aBRt7aBRt7aBRt7aBRt7";
const fixtures: Record<string, unknown> = {
  "GET /api/v1/server": { version: "test", public_key: key, domain: "agentsrv.test", protocol: { major: 1, min: 1, max: 1 } },
  "GET /api/v1/status": { workspaces: 1, nodes_total: 2, nodes_online: 1, relays_registered: 1, relays_connected: 1, certs_pending: 0, uptime_seconds: 3700 },
  "GET /api/v1/workspaces": [{ name: "home", base_domain: "home.agentsrv.test", relay: "relay-1", public_key: key, created_at: "2026-11-09T10:00:00Z", members: 2, cert: { state: "ready", domain: "*.home.agentsrv.test", workspace: "home" } }],
  "GET /api/v1/workspaces/home/tokens": [{ id: "t1", name: "laptop", roles: ["ingress"], created_at: "2026-11-09T10:00:00Z", expires_at: "2026-11-10T10:00:00Z" }],
  "GET /api/v1/workspaces/home/nodes": [{ name: "laptop", public_key: key, online: true, role_caps: ["ingress", "submitter"], joined_at: "2026-11-09T10:00:00Z" }],
  "GET /api/v1/workspaces/home/groups": [{ name: "pc", public_key: key, members: ["laptop"] }],
  "GET /api/v1/workspaces/home/routes": { version: 3, default: "direct", routes: [{ id: "r1", from: "workspace", proto: ["tls"], domains: [{ kind: "suffix", value: "example.com" }], to: "dorm" }] },
  "GET /api/v1/workspaces/home/policies": [{ id: "p1", subjects: ["group:pc"], allow: [{ exec: "office", argv: ["git", "status"] }] }],
  "GET /api/v1/workspaces/home/services": [{ name: "nas", fqdn: "nas.home.agentsrv.test", proto: "http", node: "homepc", state: "ready", public: false }],
  "GET /api/v1/workspaces/home/certs": [{ workspace: "home", domain: "*.home.agentsrv.test", state: "ready", issuer: "selfsigned" }],
  "GET /api/v1/relays": [{ name: "relay-1", url: "https://relay-1.agentsrv.test", public_key: key, connected: true }],
  "GET /api/v1/relays/tokens": [{ id: "rt1", created_at: "2026-11-09T10:00:00Z", expires_at: "2026-11-10T10:00:00Z" }],
  "POST /api/v1/workspaces/home/tokens": { id: "t2", name: "dorm", roles: [], created_at: "2026-11-09T10:00:00Z", expires_at: "2026-11-10T10:00:00Z", join_link: "agentd://home.agentsrv.test/dorm?relay=https://relay-1.agentsrv.test&key=" + key + "&token=abc" },
};

let calls: { method: string; url: string; body: string; auth: string | null }[] = [];

beforeEach(() => {
  calls = [];
  localStorage.setItem("agentd.adminToken", "secret-token");
  location.hash = "";
  vi.stubGlobal("fetch", async (input: Request) => {
    const url = new URL(input.url);
    const k = `${input.method} ${url.pathname}`;
    calls.push({ method: input.method, url: url.pathname, body: input.method === "GET" ? "" : await input.clone().text(), auth: input.headers.get("Authorization") });
    if (!(k in fixtures)) return new Response(JSON.stringify({ error: { code: "NOT_FOUND", message: k } }), { status: 404, headers: { "Content-Type": "application/json" } });
    return new Response(JSON.stringify(fixtures[k]), { status: input.method === "POST" ? 201 : 200, headers: { "Content-Type": "application/json" } });
  });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("console", () => {
  it("shows the overview with the bearer token", async () => {
    render(<App />);
    await screen.findByText("1 / 2");
    expect(screen.getByText(key)).toBeTruthy();
    expect(calls.every((c) => c.auth === "Bearer secret-token")).toBe(true);
  });

  it("renders every generated resource", async () => {
    render(<App />);
    await waitFor(() => expect(location.hash).toContain("@home"));
    const expectText: Record<string, string> = {
      workspaces: "home.agentsrv.test", tokens: "t1", nodes: "laptop", groups: "pc", routes: "suffix:example.com", policies: "p1",
      services: "nas.home.agentsrv.test", certs: "selfsigned", relays: "relay-1", "relays-tokens": "rt1",
    };
    for (const r of meta.resources) {
      location.hash = `/${r.key}@home`;
      window.dispatchEvent(new HashChangeEvent("hashchange"));
      await screen.findByRole("heading", { name: r.label });
      await screen.findAllByText(expectText[r.key], { exact: false });
    }
  });

  it("creates a join token from the generated form and shows the link once", async () => {
    location.hash = "/tokens@home";
    render(<App />);
    await screen.findByText("t1");
    fireEvent.click(screen.getByText("+ new"));
    const name = await screen.findByText("name", { selector: ".field-name" });
    fireEvent.change(name.parentElement!.querySelector("input")!, { target: { value: "dorm" } });
    fireEvent.click(screen.getByText("submit"));
    await screen.findByText(/agentd:\/\/home\.agentsrv\.test\/dorm/);
    const post = calls.find((c) => c.method === "POST");
    expect(JSON.parse(post!.body)).toEqual({ name: "dorm" });
  });

  it("renders string fields of nested policy targets as inputs", async () => {
    location.hash = "/policies@home";
    render(<App />);
    await screen.findByText("p1");
    fireEvent.click(screen.getByText("+ new"));
    fireEvent.click((await screen.findAllByText("+ add PolicyTarget", { exact: false }))[0]);
    for (const field of ["egress", "exec", "service"]) {
      const labels = await screen.findAllByText(field, { selector: ".field-name" });
      const input = labels[0].closest(".field")!.querySelector("input");
      expect(input, `${field} should be a text input`).toBeTruthy();
    }
  });
});
