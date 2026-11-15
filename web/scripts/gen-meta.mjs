// Derive UI metadata from both OpenAPI surfaces. The admin and user APIs have
// different operation IDs even when a path happens to be shared.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import YAML from "yaml";

const here = dirname(fileURLToPath(import.meta.url));
const docs = join(here, "../../docs");
const adminSpec = YAML.parse(readFileSync(join(docs, "agentserver-openapi.yaml"), "utf8"));
const specs = [
  { spec: adminSpec, out: join(here, "../src/api/meta.gen.ts"), name: "meta", source: "docs/agentserver-openapi.yaml" },
  { spec: YAML.parse(readFileSync(join(docs, "agentserver-user-openapi.yaml"), "utf8")), out: join(here, "../src/api/user-meta.gen.ts"), name: "userMeta", source: "docs/agentserver-user-openapi.yaml" },
];
const METHODS = ["get", "post", "put", "patch", "delete"];

function derefFactory(sourceSpec) {
  function deref(s, seen = [], root = sourceSpec) {
    if (!s || typeof s !== "object") return s;
    if (s.$ref) {
      const [document, pointer = ""] = s.$ref.split("#", 2);
      const targetSpec = document ? adminSpec : root;
      const parts = pointer.split("/").filter(Boolean);
      const name = parts.at(-1);
      const section = parts.at(-2);
      const target = targetSpec?.components?.[section]?.[name];
      const key = `${document}:${pointer}`;
      if (!target || seen.includes(key)) return { type: "object", title: name };
      const r = deref(target, [...seen, key], targetSpec);
      return { ...r, $name: name, ...(s.description ? { description: s.description } : {}) };
    }
    if (Array.isArray(s.allOf)) {
      const { allOf, ...rest } = s;
      const parts = allOf.map((p) => deref(p, seen, root));
      if (parts.length === 1) return { ...parts[0], ...deref(rest, seen, root) };
      const merged = { type: "object", properties: {}, required: [] };
      for (const p of parts) {
        Object.assign(merged.properties, p.properties || {});
        merged.required.push(...(p.required || []));
        if (p.$name && !merged.$name) merged.$name = p.$name;
        if (p.description && !merged.description) merged.description = p.description;
      }
      return { ...merged, ...deref(rest, seen, root) };
    }
    const o = Array.isArray(s) ? [] : {};
    for (const [k, v] of Object.entries(s)) o[k] = deref(v, seen, root);
    return o;
  }
  return deref;
}

function buildMeta(spec) {
  const deref = derefFactory(spec);
  const responseSchema = (op) => {
    for (const code of ["200", "201"]) {
      const c = op.responses?.[code]?.content?.["application/json"]?.schema;
      if (c) return deref(c);
    }
    return undefined;
  };

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
  const onlyWs = (o) => o.pathParams.every((p) => p === "ws" || p === "workspaceId");
  const tagInfo = Object.fromEntries((spec.tags || []).map((t) => [t.name, t.description || t.name]));
  const resources = [];
  const used = new Set();

  for (const op of ops) {
    if (op.method !== "GET" || !onlyWs(op) || /\{[^}]+\}$/.test(op.path)) continue;
    const shape = listShape(op.response);
    if (!shape) continue;
    const c = op.path;
    const scope = op.pathParams.some((p) => p === "ws" || p === "workspaceId") ? "workspace" : "global";
    const itemPathRe = new RegExp("^" + c.replace(/[{}]/g, "\\$&") + "/\\{([^}/]+)\\}$");
    const itemOps = ops.filter((o) => itemPathRe.test(o.path));
    const itemPath = itemOps[0]?.path;
    const idParam = itemPath ? itemPath.match(itemPathRe)[1] : undefined;
    const props = shape.item.properties || {};
    const idField = "id" in props ? "id" : "name";
    const r = {
      key: (op.path.replace(/^\/workspaces\/\{(?:ws|workspaceId)\}/, "").split("/").filter(Boolean).join("-") || "workspaces"),
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

  for (const r of resources) {
    r.title = r.title.split(/[。.\n]/)[0];
    const seg = ops.find((o) => o.id === r.list).path.split("/").filter((s) => !s.startsWith("{")).pop();
    r.label = seg === "workspaces" ? "workspaces" : seg;
    if (r.key === "relays-tokens") r.label = "relay tokens";
  }

  return {
    title: spec.info.title,
    version: spec.info.version,
    operations: Object.fromEntries(ops.map((o) => [o.id, o])),
    resources,
    singletons: ops.filter((o) => o.path === "/server" || o.path === "/status").map((o) => o.id),
  };
}

for (const { spec, out, name, source } of specs) {
  const built = buildMeta(spec);
  writeFileSync(out, `// Generated by scripts/gen-meta.mjs from ${source}. Do not edit.\nimport type { Meta } from "./meta";\n\nexport const ${name}: Meta = ${JSON.stringify(built, null, 2)};\n`);
  console.log(`${name}: ${built.resources.length} resources → ${out}`);
}
