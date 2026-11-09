// SchemaForm renders an editor for any JSON schema from the generated
// metadata: scalars, enums, arrays (of scalars, enums or objects) and nested
// objects, with a raw JSON mode for anything else.
import { useState } from "react";
import type { Schema } from "../api/meta";

type Value = unknown;

const isScalar = (s?: Schema) => !!s && ["string", "integer", "number", "boolean"].includes(s.type || "string") && !s.properties && s.type !== "array" && s.type !== "object";

export function emptyValue(s: Schema): Value {
  if (s.default !== undefined) return s.default;
  if (s.type === "array") return [];
  if (s.type === "object" || s.properties) {
    const o: Record<string, Value> = {};
    for (const k of s.required || []) {
      const p = s.properties?.[k];
      if (p) o[k] = emptyValue(p);
    }
    return o;
  }
  if (s.type === "boolean") return false;
  if (s.enum?.length) return "";
  return "";
}

// prune drops empty optional values so PATCH and create bodies stay minimal.
export function prune(s: Schema, v: Value, required = true): Value {
  if (v === undefined || v === null) return undefined;
  if (s.type === "array" && Array.isArray(v)) {
    const items = v.map((x) => (s.items ? prune(s.items, x, true) : x)).filter((x) => x !== undefined && x !== "");
    return items.length || required ? items : undefined;
  }
  if ((s.type === "object" || s.properties) && typeof v === "object") {
    const o: Record<string, Value> = {};
    for (const [k, sub] of Object.entries(s.properties || {})) {
      const req = (s.required || []).includes(k);
      const pv = prune(sub, (v as Record<string, Value>)[k], req);
      if (pv !== undefined) o[k] = pv;
    }
    return Object.keys(o).length || required ? o : undefined;
  }
  if (v === "" && !required) return undefined;
  if (s.type === "boolean" && v === false && !required) return undefined;
  return v;
}

function Help({ s }: { s: Schema }) {
  if (!s.description) return null;
  return <div className="help">{s.description}</div>;
}

function label(name: string) {
  return name.replace(/_/g, " ");
}

export function Field({ name, schema, value, onChange, required }: { name: string; schema: Schema; value: Value; onChange: (v: Value) => void; required?: boolean }) {
  const s = schema;
  const title = (
    <span className="field-name">
      {label(name)}
      {required && <span className="req">*</span>}
    </span>
  );
  if (s.readOnly) return null;
  if (s.enum && s.type !== "array") {
    return (
      <label className="field">
        {title}
        <select value={String(value ?? "")} onChange={(e) => onChange(e.target.value)}>
          {!required && <option value="">—</option>}
          {required && value === "" && <option value="">choose…</option>}
          {s.enum.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
        <Help s={s} />
      </label>
    );
  }
  if (s.type === "boolean") {
    return (
      <label className="field check">
        <input type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} />
        {title}
        <Help s={s} />
      </label>
    );
  }
  if (s.type === "integer" || s.type === "number") {
    return (
      <label className="field">
        {title}
        <input type="number" value={value === undefined || value === "" ? "" : String(value)} min={s.minimum} max={s.maximum}
          onChange={(e) => onChange(e.target.value === "" ? "" : Number(e.target.value))} />
        <Help s={s} />
      </label>
    );
  }
  if (s.type === "array") {
    const items = Array.isArray(value) ? value : [];
    const it = s.items || { type: "string" };
    if (it.enum) {
      return (
        <fieldset className="field">
          <legend>{title}</legend>
          <div className="chips">
            {it.enum.map((o) => (
              <label key={o} className="chip">
                <input type="checkbox" checked={items.includes(o)}
                  onChange={(e) => onChange(e.target.checked ? [...items, o] : items.filter((x) => x !== o))} />
                {o}
              </label>
            ))}
          </div>
          <Help s={s} />
        </fieldset>
      );
    }
    if (isScalar(it)) {
      return (
        <label className="field">
          {title}
          <input type="text" placeholder="comma separated" value={items.join(", ")}
            onChange={(e) => {
              const parts = e.target.value.split(",").map((x) => x.trim());
              onChange(it.type === "integer" || it.type === "number" ? parts.filter(Boolean).map(Number) : parts.filter((x, i) => x !== "" || i === parts.length - 1));
            }} />
          <Help s={s} />
        </label>
      );
    }
    return (
      <fieldset className="field list">
        <legend>{title}</legend>
        <Help s={s} />
        {items.map((x, i) => (
          <div key={i} className="list-item">
            <ObjectFields schema={it} value={x} onChange={(nv) => onChange(items.map((y, j) => (j === i ? nv : y)))} />
            <button type="button" className="link danger" onClick={() => onChange(items.filter((_, j) => j !== i))}>
              remove
            </button>
          </div>
        ))}
        <button type="button" className="link" onClick={() => onChange([...items, emptyValue(it)])}>
          + add {it.$name || "item"}
        </button>
      </fieldset>
    );
  }
  if (s.type === "object" || s.properties) {
    if (!s.properties) return <JsonField name={name} value={value} onChange={onChange} />;
    return (
      <fieldset className="field">
        <legend>{title}</legend>
        <Help s={s} />
        <ObjectFields schema={s} value={value} onChange={onChange} />
      </fieldset>
    );
  }
  return (
    <label className="field">
      {title}
      <input type="text" value={String(value ?? "")} pattern={s.pattern} placeholder={s.example !== undefined ? String(s.example) : ""}
        onChange={(e) => onChange(e.target.value)} />
      <Help s={s} />
    </label>
  );
}

export function ObjectFields({ schema, value, onChange }: { schema: Schema; value: Value; onChange: (v: Value) => void }) {
  const obj = (value && typeof value === "object" ? value : {}) as Record<string, Value>;
  return (
    <div className="object">
      {Object.entries(schema.properties || {}).map(([k, sub]) => (
        <Field key={k} name={k} schema={sub} required={(schema.required || []).includes(k)}
          value={obj[k] ?? (sub.type === "array" ? [] : "")} onChange={(nv) => onChange({ ...obj, [k]: nv })} />
      ))}
    </div>
  );
}

function JsonField({ name, value, onChange }: { name: string; value: Value; onChange: (v: Value) => void }) {
  const [text, setText] = useState(() => JSON.stringify(value ?? {}, null, 2));
  const [err, setErr] = useState("");
  return (
    <label className="field">
      <span className="field-name">{label(name)}</span>
      <textarea rows={6} value={text} onChange={(e) => {
        setText(e.target.value);
        try {
          onChange(JSON.parse(e.target.value));
          setErr("");
        } catch (x) {
          setErr(String(x));
        }
      }} />
      {err && <div className="error small">{err}</div>}
    </label>
  );
}

// SchemaForm edits a whole request body, with a JSON toggle.
export function SchemaForm({ schema, value, onChange }: { schema: Schema; value: Value; onChange: (v: Value) => void }) {
  const [raw, setRaw] = useState(false);
  const [text, setText] = useState("");
  const [err, setErr] = useState("");
  return (
    <div className="schema-form">
      <div className="form-mode">
        <button type="button" className={raw ? "link" : "link active"} onClick={() => setRaw(false)}>form</button>
        <button type="button" className={raw ? "link active" : "link"} onClick={() => { setText(JSON.stringify(prune(schema, value) ?? value, null, 2)); setRaw(true); }}>JSON</button>
      </div>
      {raw ? (
        <>
          <textarea className="json" rows={16} value={text} onChange={(e) => {
            setText(e.target.value);
            try {
              onChange(JSON.parse(e.target.value));
              setErr("");
            } catch (x) {
              setErr(String(x));
            }
          }} />
          {err && <div className="error small">{err}</div>}
        </>
      ) : schema.type === "array" ? (
        <Field name={schema.$name || "items"} schema={schema} value={value} onChange={onChange} />
      ) : (
        <ObjectFields schema={schema} value={value} onChange={onChange} />
      )}
    </div>
  );
}
