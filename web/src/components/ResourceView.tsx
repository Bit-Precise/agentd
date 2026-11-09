// ResourceView renders one resource from the generated metadata: a table of
// the list operation, a detail panel, and dialogs for create, replace,
// update, delete and any extra operations on the resource.
import { useCallback, useEffect, useMemo, useState } from "react";
import { call, ApiError } from "../api/client";
import { meta } from "../api/meta.gen";
import type { Operation, Resource, Schema } from "../api/meta";
import { emptyValue, prune, SchemaForm } from "./SchemaForm";
import { Cell, columns, Detail } from "./format";
import { Modal } from "./Modal";

// fit keeps only the parts of v that schema s describes (prefilling write
// bodies from read objects).
function fit(s: Schema | undefined, v: unknown): unknown {
  if (!s || v === undefined || v === null) return v;
  if (s.type === "array" && Array.isArray(v)) return v.map((x) => fit(s.items, x));
  if ((s.type === "object" || s.properties) && typeof v === "object" && s.properties) {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(s.properties)) {
      const x = (v as Record<string, unknown>)[k];
      if (x !== undefined) o[k] = fit(s.properties[k], x);
    }
    return o;
  }
  return v;
}

function verb(op: Operation): string {
  const s = op.summary.replace(/[。.]$/, "");
  return s.length > 40 ? op.id : s;
}

interface DialogState {
  op: Operation;
  path: Record<string, string>;
  body: unknown;
  query: Record<string, unknown>;
  title: string;
  after?: (result: unknown) => void;
}

export function ResourceView({ r, ws, onChanged }: { r: Resource; ws: string; onChanged?: () => void }) {
  const [data, setData] = useState<unknown>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<Record<string, unknown> | null>(null);
  const [dialog, setDialog] = useState<DialogState | null>(null);
  const [result, setResult] = useState<{ title: string; value: unknown } | null>(null);
  const ops = meta.operations;
  const baseParams = useMemo((): Record<string, string> => (r.scope === "workspace" ? { ws } : {}), [r.scope, ws]);

  const load = useCallback(async () => {
    if (r.scope === "workspace" && !ws) return;
    setLoading(true);
    setError("");
    try {
      setData(await call(r.list, { path: baseParams }));
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setLoading(false);
    }
  }, [r.list, r.scope, ws, baseParams]);

  useEffect(() => {
    setSelected(null);
    setData(null);
    load();
  }, [load]);

  const rows = useMemo(() => {
    const d = r.listField ? (data as Record<string, unknown> | null)?.[r.listField] : data;
    return (Array.isArray(d) ? d : []) as Record<string, unknown>[];
  }, [data, r.listField]);
  const cols = useMemo(() => columns(r.item), [r.item]);
  const extra = useMemo(() => {
    if (!r.listField || !data) return [] as [string, unknown][];
    return Object.entries(data as Record<string, unknown>).filter(([k]) => k !== r.listField);
  }, [data, r.listField]);

  const itemPath = (row: Record<string, unknown>) => (r.idParam ? { ...baseParams, [r.idParam]: String(row[r.idField]) } : baseParams);

  const open = (opId: string, path: Record<string, string>, body: unknown, after?: (x: unknown) => void, title?: string) => {
    const op = ops[opId];
    const q: Record<string, unknown> = {};
    for (const p of op.query) q[p.name] = p.schema.type === "boolean" ? false : "";
    setDialog({ op, path, body: body ?? (op.body ? emptyValue(op.body) : undefined), query: q, title: title || verb(op), after });
  };

  const finish = (op: Operation, res: unknown) => {
    setDialog(null);
    load();
    onChanged?.();
    const name = op.response?.$name;
    const showResult = res !== null && res !== undefined && (op.method === "GET" || (name && name !== r.item.$name && op.method === "POST"));
    if (showResult) setResult({ title: verb(op), value: res });
    if (op.method === "DELETE") setSelected(null);
  };

  return (
    <section className="resource">
      <header className="resource-head">
        <div>
          <h1>{r.label}</h1>
          <p className="muted">{r.title}</p>
        </div>
        <div className="actions">
          <button className="secondary" onClick={load} disabled={loading}>{loading ? "loading…" : "refresh"}</button>
          {r.collectionActions.map((id) => (
            <button key={id} className="secondary" onClick={() => open(id, baseParams, undefined)}>{verb(ops[id])}</button>
          ))}
          {r.replace && (
            <button className="secondary" onClick={() => open(r.replace!, baseParams, fit(ops[r.replace!].body, data), undefined, "edit all")}>edit all</button>
          )}
          {r.create && <button onClick={() => open(r.create!, baseParams, undefined, undefined, "create")}>+ new</button>}
        </div>
      </header>
      {r.scope === "workspace" && !ws && <div className="notice">Choose or create a workspace first.</div>}
      {error && <div className="error">{error}</div>}
      {extra.length > 0 && (
        <div className="extra">
          {extra.map(([k, v]) => (
            <span key={k} className="pill">{k}: <Cell value={v} /></span>
          ))}
        </div>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>{cols.map((c) => <th key={c}>{c.replace(/_/g, " ")}</th>)}<th /></tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={String(row[r.idField] ?? i)} onClick={() => setSelected(row)} className={selected === row ? "sel" : ""}>
                {cols.map((c) => <td key={c}><Cell value={row[c]} /></td>)}
                <td className="row-actions">
                  {r.remove && (
                    <button className="link danger" onClick={(e) => { e.stopPropagation(); open(r.remove!, itemPath(row), undefined, undefined, `${verb(ops[r.remove!])}: ${row[r.idField]}`); }}>delete</button>
                  )}
                </td>
              </tr>
            ))}
            {!rows.length && !loading && (
              <tr><td colSpan={cols.length + 1} className="muted center">nothing here yet</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {selected && (
        <aside className="detail">
          <header>
            <h2>{String(selected[r.idField] ?? "")}</h2>
            <button className="link" onClick={() => setSelected(null)}>✕</button>
          </header>
          <div className="actions">
            {r.update && <button className="secondary" onClick={() => open(r.update!, itemPath(selected), fit(ops[r.update!].body, selected), undefined, "edit")}>edit</button>}
            {r.itemActions.map((id) => (
              <button key={id} className="secondary" onClick={() => open(id, itemPath(selected), undefined)}>{verb(ops[id])}</button>
            ))}
          </div>
          <Detail value={selected} />
        </aside>
      )}

      {dialog && <OpDialog d={dialog} setD={setDialog} onDone={(res) => finish(dialog.op, res)} />}
      {result && (
        <Modal title={result.title} onClose={() => setResult(null)} wide>
          <p className="muted">Shown once where it contains a secret (join link, relay token). Copy it now.</p>
          {Array.isArray(result.value) ? <pre>{JSON.stringify(result.value, null, 2)}</pre> : <Detail value={result.value} />}
        </Modal>
      )}
    </section>
  );
}

function OpDialog({ d, setD, onDone }: { d: DialogState; setD: (d: DialogState | null) => void; onDone: (res: unknown) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const missing = d.op.pathParams.filter((p) => !(p in d.path));
  const [extraPath, setExtraPath] = useState<Record<string, string>>(Object.fromEntries(missing.map((p) => [p, ""])));
  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      const query: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(d.query)) if (v !== "" && v !== false) query[k] = v;
      const body = d.op.body ? prune(d.op.body, d.body) : undefined;
      onDone(await call(d.op.id, { path: { ...d.path, ...extraPath }, query, body }));
    } catch (e) {
      setError(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setBusy(false);
    }
  };
  const destructive = d.op.method === "DELETE";
  return (
    <Modal title={d.title} onClose={() => setD(null)} wide={!!d.op.body}>
      {d.op.description && <p className="muted pre">{d.op.description.trim().split("\n")[0]}</p>}
      <form onSubmit={(e) => { e.preventDefault(); submit(); }}>
        {missing.map((p) => (
          <label key={p} className="field">
            <span className="field-name">{p}<span className="req">*</span></span>
            <input value={extraPath[p]} onChange={(e) => setExtraPath({ ...extraPath, [p]: e.target.value })} required />
          </label>
        ))}
        {d.op.query.map((q) => (
          q.schema.type === "boolean" ? (
            <label key={q.name} className="field check">
              <input type="checkbox" checked={!!d.query[q.name]} onChange={(e) => setD({ ...d, query: { ...d.query, [q.name]: e.target.checked } })} />
              <span className="field-name">{q.name}</span>
              {q.description && <div className="help">{q.description}</div>}
            </label>
          ) : (
            <label key={q.name} className="field">
              <span className="field-name">{q.name}</span>
              <input value={String(d.query[q.name] ?? "")} onChange={(e) => setD({ ...d, query: { ...d.query, [q.name]: e.target.value } })} />
            </label>
          )
        ))}
        {d.op.body && <SchemaForm schema={d.op.body} value={d.body} onChange={(v) => setD({ ...d, body: v })} />}
        {destructive && <p className="warn">This cannot be undone.</p>}
        {error && <div className="error">{error}</div>}
        <div className="form-actions">
          <button type="button" className="secondary" onClick={() => setD(null)}>cancel</button>
          <button type="submit" className={destructive ? "danger" : ""} disabled={busy}>{busy ? "…" : destructive ? "delete" : "submit"}</button>
        </div>
      </form>
    </Modal>
  );
}
