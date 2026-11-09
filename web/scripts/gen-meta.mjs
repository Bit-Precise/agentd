// Derives the console's UI metadata from docs/agentserver-openapi.yaml:
// resources (collection paths with list/create/replace and item
// get/update/delete), extra actions, singleton views, and dereferenced
// schemas for form generation. The console renders everything from this file;
// no screen is hand-written per resource.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import YAML from "yaml";

const here = dirname(fileURLToPath(import.meta.url));
const specPath = join(here, "../../docs/agentserver-openapi.yaml");
const out = join(here, "../src/api/meta.gen.ts");
const spec = YAML.parse(readFileSync(specPath, "utf8"));
const METHODS = ["get", "post", "put", "patch", "delete"];

// Resolve $refs (and allOf of one ref) recursively, keeping the schema name.
function deref(s, seen = []) {
  if (!s || typeof s !== "object") return s;
  if (s.$ref) {
    const name = s.$ref.split("/").pop();
    const target = s.$ref.startsWith("#/components/parameters/")
      ? spec.components.parameters[name]
      : spec.components.schemas[name];
    if (seen.includes(name)) return { type: "object", title: name };
    const r = deref(target, [...seen, name]);
    return { ...r, $name: name, ...(s.description ? { description: s.description } : {}) };
  }
  if (Array.isArray(s.allOf)) {
    const { allOf, ...rest } = s;
    const parts = allOf.map((p) => deref(p, seen));
    // A single reference with extra keywords (description) is that schema.
    if (parts.length === 1) return { ...parts[0], ...deref(rest, seen) };
    // Otherwise merge object parts: properties and required lists combine.
    const merged = { type: "object", properties: {}, required: [] };
    for (const p of parts) {
      Object.assign(merged.properties, p.properties || {});
      merged.required.push(...(p.required || []));
      if (p.$name && !merged.$name) merged.$name = p.$name;
      if (p.description && !merged.description) merged.description = p.description;
    }
    return { ...merged, ...deref(rest, seen) };
  }
  const o = Array.isArray(s) ? [] : {};
  for (const [k, v] of Object.entries(s)) o[k] = deref(v, seen);
  return o;
}

function responseSchema(op) {
  for (const code of ["200", "201"]) {
    const c = op.responses?.[code]?.content?.["application/json"]?.schema;
    if (c) return deref(c);
  }
  return undefined;
}

const ops = [];
for (const [path, item] of Object.entries(spec.paths)) {
  const shared = (item.parameters || []).map((p) => deref(p));
  for (const m of METHODS) {
    const op = item[m];
    if (!op) continue;
    const params = [...shared, ...(op.parameters || []).map((p) => deref(p))];
    const body = op.requestBody?.content?.["application/json"]?.schema;
    ops.push({
      id: op.operationId,
      method: m.toUpperCase(),
      path,
      tag: (op.tags || ["other"])[0],
      summary: op.summary || op.operationId,
      description: op.description || "",
      pathParams: params.filter((p) => p.in === "path").map((p) => p.name),
      query: params.filter((p) => p.in === "query").map((p) => ({ name: p.name, description: p.description || "", schema: p.schema || {} })),
      body: body ? deref(body) : undefined,
      bodyRequired: !!op.requestBody?.required,
      response: responseSchema(op),
    });
  }
}

const isArrayOfObjects = (s) => s && s.type === "array" && s.items && (s.items.type === "object" || s.items.properties);
const listShape = (s) => {
  if (isArrayOfObjects(s)) return { item: s.items, field: undefined };
  if (s && s.type === "object" && s.properties) {
    for (const [k, v] of Object.entries(s.properties)) if (isArrayOfObjects(v)) return { item: v.items, field: k };
  }
  return undefined;
};
const onlyWs = (o) => o.pathParams.every((p) => p === "ws");
const tagInfo = Object.fromEntries((spec.tags || []).map((t) => [t.name, t.description || t.name]));

const resources = [];
const used = new Set();
for (const op of ops) {
  if (op.method !== "GET" || !onlyWs(op) || /\{[^}]+\}$/.test(op.path)) continue;
  const shape = listShape(op.response);
  if (!shape) continue;
  const c = op.path;
  const scope = op.pathParams.includes("ws") ? "workspace" : "global";
  const itemPathRe = new RegExp("^" + c.replace(/[{}]/g, "\\$&") + "/\\{([^}/]+)\\}$");
  const itemOps = ops.filter((o) => itemPathRe.test(o.path));
  const itemPath = itemOps[0]?.path;
  const idParam = itemPath ? itemPath.match(itemPathRe)[1] : undefined;
  const props = shape.item.properties || {};
  const idField = "id" in props ? "id" : "name";
  const r = {
    key: (op.path.replace("/workspaces/{ws}", "").split("/").filter(Boolean).join("-") || "workspaces"),
    tag: op.tag,
    title: tagInfo[op.tag] || op.tag,
    scope,
    list: op.id,
    listField: shape.field,
    item: shape.item,
    idField,
    idParam,
    create: ops.find((o) => o.path === c && o.method === "POST")?.id,
    replace: ops.find((o) => o.path === c && o.method === "PUT")?.id,
    get: itemOps.find((o) => o.method === "GET")?.id,
    update: itemOps.find((o) => o.method === "PATCH")?.id,
    remove: itemOps.find((o) => o.method === "DELETE")?.id,
    itemActions: [],
    collectionActions: [],
  };
  for (const id of [r.list, r.create, r.replace, r.get, r.update, r.remove]) if (id) used.add(id);
  resources.push(r);
}
// Remaining operations become actions of the resource whose path they extend.
for (const op of ops) {
  if (used.has(op.id) || op.path === "/server" || op.path === "/status") continue;
  let best;
  for (const r of resources) {
    const listOp = ops.find((o) => o.id === r.list);
    if (op.path.startsWith(listOp.path + "/") && (!best || listOp.path.length > ops.find((o) => o.id === best.list).path.length)) best = r;
  }
  if (!best) continue;
  const listPath = ops.find((o) => o.id === best.list).path;
  const rest = op.path.slice(listPath.length + 1);
  if (rest.startsWith("{")) best.itemActions.push(op.id);
  else best.collectionActions.push(op.id);
  used.add(op.id);
}
// Short titles: the first sentence of the tag description.
for (const r of resources) {
  r.title = r.title.split(/[。.\n]/)[0];
  const seg = ops.find((o) => o.id === r.list).path.split("/").filter((s) => !s.startsWith("{")).pop();
  r.label = seg === "workspaces" ? "workspaces" : seg;
  if (r.key === "relays-tokens") r.label = "relay tokens";
}

const singletons = ops.filter((o) => o.path === "/server" || o.path === "/status").map((o) => o.id);
const meta = {
  title: spec.info.title,
  version: spec.info.version,
  operations: Object.fromEntries(ops.map((o) => [o.id, o])),
  resources,
  singletons,
};
writeFileSync(
  out,
  "// Generated by scripts/gen-meta.mjs from docs/agentserver-openapi.yaml. Do not edit.\n" +
    "import type { Meta } from \"./meta\";\n\n" +
    "export const meta: Meta = " + JSON.stringify(meta, null, 2) + ";\n",
);
console.log(`meta: ${resources.length} resources, ${ops.length} operations → ${out}`);
