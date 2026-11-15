// SchemaForm renders generated JSON schemas using shadcn form primitives.
import { useState } from "react";
import type { Schema } from "../api/meta";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import { Checkbox } from "./ui/checkbox";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Textarea } from "./ui/textarea";

type Value = unknown;
const isScalar = (schema?: Schema) => Boolean(schema && ["string", "integer", "number", "boolean"].includes(schema.type || "string") && !schema.properties && schema.type !== "array" && schema.type !== "object");

export function emptyValue(schema: Schema): Value {
  if (schema.default !== undefined) return schema.default;
  if (schema.type === "array") return [];
  if (schema.type === "object" || schema.properties) {
    const output: Record<string, Value> = {};
    for (const key of schema.required || []) {
      const property = schema.properties?.[key];
      if (property) output[key] = emptyValue(property);
    }
    return output;
  }
  if (schema.type === "boolean") return false;
  return "";
}

export function prune(schema: Schema, value: Value, required = true): Value {
  if (value === undefined || value === null) return undefined;
  if (schema.type === "array" && Array.isArray(value)) {
    const items = value.map((item) => (schema.items ? prune(schema.items, item, true) : item)).filter((item) => item !== undefined && item !== "");
    return items.length || required ? items : undefined;
  }
  if ((schema.type === "object" || schema.properties) && typeof value === "object") {
    const output: Record<string, Value> = {};
    for (const [key, property] of Object.entries(schema.properties || {})) {
      const item = prune(property, (value as Record<string, Value>)[key], (schema.required || []).includes(key));
      if (item !== undefined) output[key] = item;
    }
    return Object.keys(output).length || required ? output : undefined;
  }
  if (value === "" && !required) return undefined;
  if (schema.type === "boolean" && value === false && !required) return undefined;
  return value;
}

function Help({ schema }: { schema: Schema }) {
  return schema.description ? <p className="text-xs whitespace-pre-wrap text-muted-foreground">{schema.description}</p> : null;
}

function label(name: string) {
  return name.replace(/_/g, " ");
}

function FieldTitle({ name, required }: { name: string; required?: boolean }) {
  return <span className="capitalize">{label(name)}{required && <span className="ml-0.5 text-destructive">*</span>}</span>;
}

export function Field({ name, schema, value, onChange, required }: { name: string; schema: Schema; value: Value; onChange: (value: Value) => void; required?: boolean }) {
  if (schema.readOnly) return null;
  if (schema.enum && schema.type !== "array") {
    return <div className="grid gap-2"><Label htmlFor={`field-${name}`}><FieldTitle name={name} required={required} /></Label><Select value={String(value ?? "")} onValueChange={onChange}><SelectTrigger id={`field-${name}`}><SelectValue placeholder={required ? "Choose…" : "—"} /></SelectTrigger><SelectContent>{schema.enum.map((option) => <SelectItem key={option} value={option}>{option}</SelectItem>)}</SelectContent></Select><Help schema={schema} /></div>;
  }
  if (schema.type === "boolean") {
    return <div className="grid gap-1"><Label className="flex items-center gap-2"><Checkbox checked={Boolean(value)} onCheckedChange={(checked) => onChange(checked === true)} /><FieldTitle name={name} required={required} /></Label><Help schema={schema} /></div>;
  }
  if (schema.type === "integer" || schema.type === "number") {
    return <div className="grid gap-2"><Label htmlFor={`field-${name}`}><FieldTitle name={name} required={required} /></Label><Input id={`field-${name}`} type="number" value={value === undefined || value === "" ? "" : String(value)} min={schema.minimum} max={schema.maximum} onChange={(event) => onChange(event.target.value === "" ? "" : Number(event.target.value))} /><Help schema={schema} /></div>;
  }
  if (schema.type === "array") {
    const items = Array.isArray(value) ? value : [];
    const itemSchema = schema.items || { type: "string" };
    if (itemSchema.enum) {
      return <fieldset className="grid gap-3 rounded-lg border p-4"><legend className="px-1 text-sm font-medium"><FieldTitle name={name} required={required} /></legend><div className="flex flex-wrap gap-3">{itemSchema.enum.map((option) => <Label key={option} className="flex items-center gap-2 font-normal"><Checkbox checked={items.includes(option)} onCheckedChange={(checked) => onChange(checked === true ? [...items, option] : items.filter((item) => item !== option))} />{option}</Label>)}</div><Help schema={schema} /></fieldset>;
    }
    if (isScalar(itemSchema)) {
      return <div className="grid gap-2"><Label htmlFor={`field-${name}`}><FieldTitle name={name} required={required} /></Label><Input id={`field-${name}`} placeholder="Comma separated" value={items.join(", ")} onChange={(event) => { const parts = event.target.value.split(",").map((part) => part.trim()); onChange(itemSchema.type === "integer" || itemSchema.type === "number" ? parts.filter(Boolean).map(Number) : parts.filter((part, index) => part !== "" || index === parts.length - 1)); }} /><Help schema={schema} /></div>;
    }
    return <fieldset className="grid gap-3 rounded-lg border p-4"><legend className="px-1 text-sm font-medium"><FieldTitle name={name} required={required} /></legend><Help schema={schema} />{items.map((item, index) => <Card key={index} size="sm"><CardContent className="grid gap-3 p-3"><ObjectFields schema={itemSchema} value={item} onChange={(next) => onChange(items.map((current, itemIndex) => itemIndex === index ? next : current))} /><Button type="button" variant="link" className="justify-self-start px-0 text-destructive" onClick={() => onChange(items.filter((_, itemIndex) => itemIndex !== index))}>Remove</Button></CardContent></Card>)}<Button type="button" variant="outline" className="justify-self-start" onClick={() => onChange([...items, emptyValue(itemSchema)])}>Add {itemSchema.$name || "item"}</Button></fieldset>;
  }
  if (schema.type === "object" || schema.properties) {
    if (!schema.properties) return <JsonField name={name} value={value} onChange={onChange} />;
    return <fieldset className="grid gap-3 rounded-lg border p-4"><legend className="px-1 text-sm font-medium"><FieldTitle name={name} required={required} /></legend><Help schema={schema} /><ObjectFields schema={schema} value={value} onChange={onChange} /></fieldset>;
  }
  return <div className="grid gap-2"><Label htmlFor={`field-${name}`}><FieldTitle name={name} required={required} /></Label><Input id={`field-${name}`} type="text" value={String(value ?? "")} pattern={schema.pattern} placeholder={schema.example !== undefined ? String(schema.example) : ""} onChange={(event) => onChange(event.target.value)} /><Help schema={schema} /></div>;
}

export function ObjectFields({ schema, value, onChange }: { schema: Schema; value: Value; onChange: (value: Value) => void }) {
  const object = (value && typeof value === "object" ? value : {}) as Record<string, Value>;
  return <div className="grid gap-4">{Object.entries(schema.properties || {}).map(([key, property]) => <Field key={key} name={key} schema={property} required={(schema.required || []).includes(key)} value={object[key] ?? (property.type === "array" ? [] : "")} onChange={(next) => onChange({ ...object, [key]: next })} />)}</div>;
}

function JsonField({ name, value, onChange }: { name: string; value: Value; onChange: (value: Value) => void }) {
  const [text, setText] = useState(() => JSON.stringify(value ?? {}, null, 2));
  const [error, setError] = useState("");
  return <div className="grid gap-2"><Label htmlFor={`json-${name}`}><FieldTitle name={name} /></Label><Textarea id={`json-${name}`} rows={6} value={text} onChange={(event) => { setText(event.target.value); try { onChange(JSON.parse(event.target.value)); setError(""); } catch (cause) { setError(String(cause)); } }} />{error && <p className="text-xs text-destructive">{error}</p>}</div>;
}

export function SchemaForm({ schema, value, onChange }: { schema: Schema; value: Value; onChange: (value: Value) => void }) {
  const [raw, setRaw] = useState(false);
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  return <div className="grid gap-4"><div className="flex justify-end gap-1"><Button type="button" variant={raw ? "ghost" : "secondary"} size="sm" onClick={() => setRaw(false)}>Form</Button><Button type="button" variant={raw ? "secondary" : "ghost"} size="sm" onClick={() => { setText(JSON.stringify(prune(schema, value) ?? value, null, 2)); setRaw(true); }}>JSON</Button></div>{raw ? <div className="grid gap-2"><Textarea className="font-mono text-xs" rows={16} value={text} onChange={(event) => { setText(event.target.value); try { onChange(JSON.parse(event.target.value)); setError(""); } catch (cause) { setError(String(cause)); } }} />{error && <p className="text-xs text-destructive">{error}</p>}</div> : schema.type === "array" ? <Field name={schema.$name || "items"} schema={schema} value={value} onChange={onChange} /> : <ObjectFields schema={schema} value={value} onChange={onChange} />}</div>;
}
