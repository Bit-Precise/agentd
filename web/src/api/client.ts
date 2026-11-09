// The API client is openapi-fetch typed by the generated schema
// (src/api/schema.gen.ts). The generic resource engine calls operations by
// id through `call`, which looks the method and path up in the generated
// metadata.
import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "./schema.gen";
import { meta } from "./meta.gen";

const TOKEN_KEY = "agentd.adminToken";

export function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

export function setToken(t: string) {
  try {
    if (t) localStorage.setItem(TOKEN_KEY, t);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable: the token lives for this page only */
  }
  memToken = t;
}

let memToken = getToken();

const auth: Middleware = {
  onRequest({ request }) {
    const t = getToken() || memToken;
    if (t) request.headers.set("Authorization", `Bearer ${t}`);
    return request;
  },
};

export const api = createClient<paths>({
  baseUrl: new URL("/api/v1", location.origin).toString(),
  // Resolve fetch per call (lets tests and polyfills replace it).
  fetch: (req: Request) => globalThis.fetch(req),
});
api.use(auth);

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

function toError(status: number, body: unknown): ApiError {
  const e = (body as { error?: { code?: string; message?: string } })?.error;
  return new ApiError(status, e?.code || String(status), e?.message || `HTTP ${status}`);
}

export interface CallArgs {
  path?: Record<string, string>;
  query?: Record<string, unknown>;
  body?: unknown;
}

// call runs an operation by its operationId.
export async function call(opId: string, args: CallArgs = {}): Promise<unknown> {
  const op = meta.operations[opId];
  if (!op) throw new Error(`unknown operation ${opId}`);
  // Dynamic dispatch over the typed client; paths come from the same spec.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const fn = (api as any)[op.method] as (url: string, init: unknown) => Promise<{ data?: unknown; error?: unknown; response: Response }>;
  const { data, error, response } = await fn(op.path, {
    params: { path: args.path || {}, query: args.query || {} },
    body: args.body,
  });
  if (!response.ok) throw toError(response.status, error);
  return data ?? null;
}

// Typed calls used by the dashboard.
export async function serverInfo() {
  const { data, error, response } = await api.GET("/server");
  if (!response.ok || !data) throw toError(response.status, error);
  return data;
}

export async function status() {
  const { data, error, response } = await api.GET("/status");
  if (!response.ok || !data) throw toError(response.status, error);
  return data;
}

export async function workspaces() {
  const { data, error, response } = await api.GET("/workspaces");
  if (!response.ok || !data) throw toError(response.status, error);
  return data;
}
