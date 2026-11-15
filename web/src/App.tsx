import { useCallback, useEffect, useState } from "react";
import { meta } from "./api/meta.gen";
import { getToken, setToken, workspaces, ApiError } from "./api/client";
import { ResourceView } from "./components/ResourceView";
import { Dashboard } from "./components/Dashboard";
import { Button } from "./components/ui/button";
import { Select } from "./components/ui/select";
import { Input } from "./components/ui/input";

function readHash() {
  const h = decodeURIComponent(location.hash.replace(/^#\/?/, ""));
  const [view, ws] = h.split("@");
  return { view: view || "overview", ws: ws || "" };
}

export function App() {
  const [token, setTok] = useState(getToken());
  const [authenticated, setAuthenticated] = useState(() => !!getToken());
  const [authError, setAuthError] = useState("");
  const [wsList, setWsList] = useState<{ id: string; name: string }[]>([]);
  const [{ view, ws }, setRoute] = useState(readHash());

  useEffect(() => {
    if (token) { setAuthenticated(true); return; }
    fetch("/auth/me", { credentials: "same-origin" }).then((r) => setAuthenticated(r.ok)).catch(() => setAuthenticated(false));
  }, [token]);

  useEffect(() => {
    const f = () => setRoute(readHash());
    addEventListener("hashchange", f);
    return () => removeEventListener("hashchange", f);
  }, []);

  const go = (v: string, w = ws) => {
    location.hash = `/${v}${w ? "@" + w : ""}`;
  };

  const loadWs = useCallback(async () => {
    try {
      const list = await workspaces();
      const workspaceItems = list.map((w) => ({ id: w.id || w.name, name: w.name }));
      setWsList(workspaceItems);
      setAuthError("");
      const current = workspaceItems.find((item) => item.id === ws || item.name === ws);
      if (current && current.id !== ws) go(view, current.id);
      else if (!ws && workspaceItems.length) go(view, workspaceItems[0].id);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setAuthError("The admin token was rejected.");
        setTok("");
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ws, view]);

  useEffect(() => {
    if (token) loadWs();
  }, [token, loadWs]);

  if (!authenticated) return <Login error={authError} onLogin={(t) => { setToken(t); setTok(t); setAuthenticated(true); }} />;

  const global = meta.resources.filter((r) => r.scope === "global");
  const scoped = meta.resources.filter((r) => r.scope === "workspace");
  const current = meta.resources.find((r) => r.key === view);

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="brand">agentserver</div>
        <a className={view === "overview" ? "active" : ""} onClick={() => go("overview")}>overview</a>
        {global.map((r) => (
          <a key={r.key} className={view === r.key ? "active" : ""} onClick={() => go(r.key)}>{r.label}</a>
        ))}
        <div className="ws-picker">
          <label>workspace</label>
          <Select value={ws} onChange={(e) => go(view, e.target.value)}>
            {!wsList.length && <option value="">none yet</option>}
            {wsList.map((w) => <option key={w.id} value={w.id}>{w.name}</option>)}
          </Select>
        </div>
        {scoped.map((r) => (
          <a key={r.key} className={view === r.key ? "active" : ""} onClick={() => go(r.key)}>{r.label}</a>
        ))}
        <div className="spacer" />
        <Button variant="ghost" className="muted" onClick={() => { fetch("/auth/logout", { credentials: "same-origin" }).catch(() => undefined); setToken(""); setTok(""); setAuthenticated(false); }}>sign out</Button>
        <div className="muted small">API {meta.version}</div>
      </nav>
      <main>
        {current ? <ResourceView key={current.key + ws} r={current} ws={ws} onChanged={current.key === "workspaces" ? loadWs : undefined} /> : <Dashboard />}
      </main>
    </div>
  );
}

function Login({ onLogin, error }: { onLogin: (t: string) => void; error: string }) {
  const [t, setT] = useState("");
  const [oidc, setOidc] = useState(false);
  useEffect(() => { fetch("/auth/config", { credentials: "same-origin" }).then((r) => r.json()).then((v) => setOidc(!!v.oidc_enabled)).catch(() => undefined); }, []);
  return (
    <div className="login">
      <form onSubmit={(e) => { e.preventDefault(); if (t.trim()) onLogin(t.trim()); }}>
        <h1>agentserver</h1>
        {oidc ? <>
          <p className="muted">Sign in with the configured OIDC provider.</p>
          <Button asChild><a href="/auth/login">Sign in with OIDC</a></Button>
        </> : <>
          <p className="muted">Enter the admin token (the value of AGENTSERVER_ADMIN_TOKEN).</p>
          <Input type="password" autoFocus value={t} onChange={(e) => setT(e.target.value)} placeholder="admin token" />
          {error && <div className="error">{error}</div>}
          <Button type="submit">sign in</Button>
          <a className="oidc-login" href="/auth/login">Sign in with OIDC</a>
        </>}
      </form>
    </div>
  );
}
