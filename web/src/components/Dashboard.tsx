import { useEffect, useState } from "react";
import { serverInfo, status, ApiError } from "../api/client";
import { copy } from "./format";

type Info = Awaited<ReturnType<typeof serverInfo>>;
type Stat = Awaited<ReturnType<typeof status>>;

export function Dashboard() {
  const [info, setInfo] = useState<Info | null>(null);
  const [stat, setStat] = useState<Stat | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    const tick = async () => {
      try {
        const [i, s] = await Promise.all([serverInfo(), status()]);
        if (live) {
          setInfo(i);
          setStat(s);
          setError("");
        }
      } catch (e) {
        if (live) setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
      }
    };
    tick();
    const t = setInterval(tick, 10000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, []);
  const up = stat?.uptime_seconds ?? 0;
  const cards: [string, string | number | undefined][] = [
    ["workspaces", stat?.workspaces],
    ["nodes online", stat ? `${stat.nodes_online ?? 0} / ${stat.nodes_total ?? 0}` : undefined],
    ["relays connected", stat ? `${stat.relays_connected ?? 0} / ${stat.relays_registered ?? 0}` : undefined],
    ["certificates pending", stat?.certs_pending],
    ["uptime", stat ? `${Math.floor(up / 3600)}h ${Math.floor((up % 3600) / 60)}m` : undefined],
  ];
  return (
    <section className="resource">
      <header className="resource-head">
        <div>
          <h1>overview</h1>
          <p className="muted">{info ? `agentserver ${info.version} · ${info.domain ?? ""}` : "…"}</p>
        </div>
      </header>
      {error && <div className="error">{error}</div>}
      <div className="cards">
        {cards.map(([k, v]) => (
          <div key={k} className="card">
            <div className="card-value">{v ?? "—"}</div>
            <div className="card-label">{k}</div>
          </div>
        ))}
      </div>
      {info && (
        <div className="panel">
          <h2>agentserver key</h2>
          <p className="muted">Relays pin this key (control.public_key). Nodes never see it: they pin their workspace key.</p>
          <code className="copyable" onClick={() => copy(info.public_key)} title="click to copy">{info.public_key}</code>
        </div>
      )}
      <div className="panel">
        <h2>getting started</h2>
        <ol className="steps">
          <li>Register a relay under <b>relays</b> (or start agentrelay with a relay token from <b>relay tokens</b>).</li>
          <li>Create a workspace and assign the relay.</li>
          <li>Create a join token under <b>tokens</b> and run <code>agentd join '&lt;link&gt;'</code> on each machine.</li>
          <li>Add routes and policies; nodes pick them up immediately.</li>
        </ol>
      </div>
    </section>
  );
}
