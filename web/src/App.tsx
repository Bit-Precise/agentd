import { useCallback, useEffect, useState } from "react";
import { meta } from "./api/meta.gen";
import { authConfig, authMe, getToken, setToken, userWorkspaces, workspaces, type AuthMe, ApiError } from "./api/client";
import { ResourceView } from "./components/ResourceView";
import { Dashboard } from "./components/Dashboard";
import { Button } from "./components/ui/button";
import { Select } from "./components/ui/select";
import { Input } from "./components/ui/input";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "./components/ui/dropdown-menu";

type WorkspaceOption = { id: string; name: string };

function readRoute() {
  const path = decodeURIComponent(location.pathname.replace(/^\/+|\/+$/g, ""));
  const parts = path.split("/");
  return { view: parts[0] || "overview", ws: parts[1] || "" };
}
function routePath(view: string, ws: string) {
  if (view === "overview") return "/";
  return ws ? "/" + encodeURIComponent(view) + "/" + encodeURIComponent(ws) : "/" + encodeURIComponent(view);
}

export function App() {
  const initialToken = getToken();
  const [token, setTok] = useState(initialToken);
  const [authenticated, setAuthenticated] = useState(() => !!initialToken);
  const [authError, setAuthError] = useState("");
  const [identity, setIdentity] = useState<AuthMe | null>(null);
  const [adminMode, setAdminMode] = useState(() => localStorage.getItem("agentd.adminMode") === "true" || !!initialToken);
  const [dark, setDark] = useState(() => localStorage.getItem("agentd.theme") === "dark");
  const [wsList, setWsList] = useState<WorkspaceOption[]>([]);
  const [{ view, ws }, setRoute] = useState(readRoute());

  useEffect(() => { document.documentElement.dataset.theme = dark ? "dark" : "light"; localStorage.setItem("agentd.theme", dark ? "dark" : "light"); }, [dark]);
  useEffect(() => { const update = () => setRoute(readRoute()); addEventListener("popstate", update); return () => removeEventListener("popstate", update); }, []);
  useEffect(() => { authMe().then((me) => { setIdentity(me); if (me) { setAuthenticated(true); if (me.instance_admin && localStorage.getItem("agentd.adminMode") === null) setAdminMode(true); } }).catch(() => undefined); authConfig().catch(() => undefined); }, []);

  const go = useCallback((nextView: string, nextWs = ws) => { history.pushState({}, "", routePath(nextView, nextWs)); dispatchEvent(new PopStateEvent("popstate")); }, [ws]);
  const loadWs = useCallback(async () => {
    try {
      const list = adminMode ? await workspaces() : await userWorkspaces();
      const items = list.map((w) => ({ id: w.id || w.name, name: w.name }));
      setWsList(items); setAuthError("");
      const current = items.find((item) => item.id === ws || item.name === ws);
      if (current && current.id !== ws) go(view, current.id);
      else if (!ws && items.length) go(view, items[0].id);
      else if (ws && !current && view !== "overview") go("overview", "");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) { setAuthError("Your session has expired."); setAuthenticated(false); setTok(""); }
    }
  }, [adminMode, go, view, ws]);
  useEffect(() => { if (authenticated) loadWs(); }, [authenticated, loadWs]);

  const setMode = (admin: boolean) => { setAdminMode(admin); localStorage.setItem("agentd.adminMode", String(admin)); go(admin ? "overview" : "members", ws); };
  const logout = () => { fetch("/auth/logout", { credentials: "same-origin" }).catch(() => undefined); setToken(""); setTok(""); setAuthenticated(false); setIdentity(null); go("overview", ""); };
  if (!authenticated) return <Login error={authError} onLogin={(t) => { setToken(t); setTok(t); setAuthenticated(true); setAdminMode(true); }} />;

  const global = adminMode ? meta.resources.filter((r) => r.scope === "global") : [];
  const allowedUserResources = new Set(["members", "nodes", "routes", "policies", "services"]);
  const scoped = meta.resources.filter((r) => r.scope === "workspace" && (adminMode || allowedUserResources.has(r.key)));
  const current = meta.resources.find((r) => r.key === view && (adminMode || r.scope === "workspace" && allowedUserResources.has(r.key)));
  const readOnly = !adminMode && ["nodes", "services"].includes(view);

  return <div className="app"><nav className="sidebar"><div className="brand">agentserver</div><div className="ws-picker"><label>workspace</label><Select value={ws} onChange={(e) => go(view === "overview" ? (adminMode ? "workspaces" : "members") : view, e.target.value)}>{!wsList.length && <option value="">none yet</option>}{wsList.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}</Select></div>{adminMode && <a className={view === "overview" ? "active" : ""} onClick={() => go("overview", "")}>overview</a>}{global.map((r) => <a key={r.key} className={view === r.key ? "active" : ""} onClick={() => go(r.key, "")}>{r.label}</a>)}{scoped.map((r) => <a key={r.key} className={view === r.key ? "active" : ""} onClick={() => go(r.key, ws)}>{r.label}</a>)}<div className="spacer" /><UserMenu identity={identity} adminMode={adminMode} canAdmin={!!identity?.instance_admin || !!token} dark={dark} onDark={setDark} onAdmin={() => setMode(!adminMode)} onLogout={logout} /><div className="muted small">API {meta.version}</div></nav><main>{current ? <ResourceView key={current.key + ws + adminMode} r={current} ws={ws} surface={adminMode ? "admin" : "user"} readOnly={readOnly} onChanged={current.key === "workspaces" ? loadWs : undefined} /> : adminMode ? <Dashboard /> : <UserHome identity={identity} />}</main></div>;
}

function UserHome({ identity }: { identity: AuthMe | null }) { return <section className="resource"><header className="resource-head"><div><h1>workspace</h1><p className="muted">{identity?.name || identity?.email || "Signed in"}. Choose a workspace above.</p></div></header><div className="panel">Select a workspace to view the resources you can access.</div></section>; }

function UserMenu({ identity, adminMode, canAdmin, dark, onDark, onAdmin, onLogout }: { identity: AuthMe | null; adminMode: boolean; canAdmin: boolean; dark: boolean; onDark: (dark: boolean) => void; onAdmin: () => void; onLogout: () => void }) { const label = identity?.name || identity?.email || (canAdmin ? "Instance admin" : "User"); return <DropdownMenu><DropdownMenuTrigger asChild><button className="identity-menu"><span className="avatar">{label.slice(0, 1).toUpperCase()}</span><span className="identity-copy"><b>{label}</b>{identity?.email && identity.name && <small>{identity.email}</small>}</span></button></DropdownMenuTrigger><DropdownMenuContent align="start"><DropdownMenuItem onSelect={() => onDark(!dark)}>{dark ? "Light mode" : "Dark mode"}</DropdownMenuItem>{canAdmin && <DropdownMenuItem onSelect={onAdmin}>{adminMode ? "Workspace mode" : "Admin mode"}</DropdownMenuItem>}<DropdownMenuSeparator /><DropdownMenuItem onSelect={onLogout}>Log out</DropdownMenuItem></DropdownMenuContent></DropdownMenu>; }

function Login({ onLogin, error }: { onLogin: (t: string) => void; error: string }) { const [t, setT] = useState(""); const [oidc, setOidc] = useState(false); useEffect(() => { fetch("/auth/config", { credentials: "same-origin" }).then((r) => r.json()).then((v) => setOidc(!!v.oidc_enabled)).catch(() => undefined); }, []); return <div className="login"><form onSubmit={(e) => { e.preventDefault(); if (t.trim()) onLogin(t.trim()); }}><h1>agentserver</h1>{oidc ? <><p className="muted">Sign in with the configured OIDC provider.</p><Button asChild><a href="/auth/login">Sign in with OIDC</a></Button></> : <><p className="muted">Enter the admin token (the value of AGENTSERVER_ADMIN_TOKEN).</p><Input type="password" autoFocus value={t} onChange={(e) => setT(e.target.value)} placeholder="admin token" />{error && <div className="error">{error}</div>}<Button type="submit">sign in</Button><a className="oidc-login" href="/auth/login">Sign in with OIDC</a></>}</form></div>; }
