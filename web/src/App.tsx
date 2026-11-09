import { useCallback, useEffect, useState } from "react";
import { meta } from "./api/meta.gen";
import { getToken, setToken, workspaces, ApiError } from "./api/client";
import { ResourceView } from "./components/ResourceView";
import { Dashboard } from "./components/Dashboard";

function readHash() {
  const h = decodeURIComponent(location.hash.replace(/^#\/?/, ""));
  const [view, ws] = h.split("@");
  return { view: view || "overview", ws: ws || "" };
}

export function App() {
  const [token, setTok] = useState(getToken());
  const [authError, setAuthError] = useState("");
  const [wsList, setWsList] = useState<string[]>([]);
  const [{ view, ws }, setRoute] = useState(readHash());

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
      const names = list.map((w) => w.name);
      setWsList(names);
      setAuthError("");
      if (!ws && names.length) go(view, names[0]);
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

  if (!token) return <Login error={authError} onLogin={(t) => { setToken(t); setTok(t); }} />;

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
          <select value={ws} onChange={(e) => go(view, e.target.value)}>
            {!wsList.length && <option value="">none yet</option>}
            {wsList.map((w) => <option key={w} value={w}>{w}</option>)}
          </select>
        </div>
        {scoped.map((r) => (
          <a key={r.key} className={view === r.key ? "active" : ""} onClick={() => go(r.key)}>{r.label}</a>
        ))}
        <div className="spacer" />
        <a className="muted" onClick={() => { setToken(""); setTok(""); }}>sign out</a>
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
  return (
    <div className="login">
      <form onSubmit={(e) => { e.preventDefault(); if (t.trim()) onLogin(t.trim()); }}>
        <h1>agentserver</h1>
        <p className="muted">Enter the admin token (the value of AGENTSERVER_ADMIN_TOKEN).</p>
        <input type="password" autoFocus value={t} onChange={(e) => setT(e.target.value)} placeholder="admin token" />
        {error && <div className="error">{error}</div>}
        <button type="submit">sign in</button>
      </form>
    </div>
  );
}
