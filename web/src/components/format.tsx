// Cell and detail rendering for arbitrary API values.
import type { Schema } from "../api/meta";

const KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

export function copy(text: string) {
  navigator.clipboard?.writeText(text).catch(() => undefined);
}

export function Cell({ value }: { value: unknown }) {
  if (value === null || value === undefined || value === "") return <span className="muted">—</span>;
  if (typeof value === "boolean") return value ? <span className="dot on" title="yes">●</span> : <span className="dot" title="no">○</span>;
  if (typeof value === "number") return <span>{value}</span>;
  if (typeof value === "string") {
    if (KEY_RE.test(value))
      return (
        <code className="key" title={`${value} (click to copy)`} onClick={(e) => { e.stopPropagation(); copy(value); }}>
          {value.slice(0, 10)}…
        </code>
      );
    if (TIME_RE.test(value)) return <span title={value}>{new Date(value).toLocaleString()}</span>;
    return <span>{value}</span>;
  }
  if (Array.isArray(value)) {
    if (!value.length) return <span className="muted">—</span>;
    return (
      <span className="tags">
        {value.map((v, i) => (
          <span key={i} className="tag">{summarize(v)}</span>
        ))}
      </span>
    );
  }
  return <span>{summarize(value)}</span>;
}

export function summarize(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v !== "object") return String(v);
  if (Array.isArray(v)) return v.map(summarize).join(", ");
  const o = v as Record<string, unknown>;
  if ("kind" in o && "value" in o) return `${o.kind}:${o.value}`;
  if ("state" in o) return String(o.state);
  if ("status" in o) return String(o.status);
  const parts = Object.entries(o)
    .filter(([, x]) => x !== undefined && x !== null && x !== "" && !(Array.isArray(x) && !x.length) && x !== false)
    .map(([k, x]) => (x === true ? k : `${k}=${summarize(x)}`));
  return parts.join(" ");
}

// columns picks up to eight properties worth a table column.
export function columns(s: Schema): string[] {
  const props = s.properties || {};
  const req = s.required || [];
  const names = Object.keys(props).sort((a, b) => Number(req.includes(b)) - Number(req.includes(a)));
  const good = names.filter((n) => {
    const p = props[n];
    if (p.type === "object" && p.properties && !("state" in p.properties) && !("status" in p.properties)) return false;
    return !["uri_key", "uri_name", "joined_at", "created_at", "connected_since", "policy_sources", "executor"].includes(n);
  });
  return good.slice(0, 8);
}

export function Detail({ value }: { value: unknown }) {
  if (!value || typeof value !== "object") return <Cell value={value} />;
  return (
    <dl className="kv">
      {Object.entries(value as Record<string, unknown>).map(([k, v]) => (
        <div key={k} className="kv-row">
          <dt>{k.replace(/_/g, " ")}</dt>
          <dd>
            {typeof v === "object" && v !== null && !Array.isArray(v) ? (
              <pre>{JSON.stringify(v, null, 2)}</pre>
            ) : Array.isArray(v) && v.some((x) => typeof x === "object") ? (
              <pre>{JSON.stringify(v, null, 2)}</pre>
            ) : typeof v === "string" && (KEY_RE.test(v) || v.startsWith("agentd://") || v.length > 60) ? (
              <code className="copyable" onClick={() => copy(v)} title="click to copy">{v}</code>
            ) : (
              <Cell value={v} />
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}
