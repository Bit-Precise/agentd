// Types of the generated UI metadata (src/api/meta.gen.ts).

export interface Schema {
  type?: string;
  $name?: string;
  title?: string;
  description?: string;
  properties?: Record<string, Schema>;
  required?: string[];
  items?: Schema;
  enum?: string[];
  format?: string;
  pattern?: string;
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  default?: unknown;
  example?: unknown;
  readOnly?: boolean;
  nullable?: boolean;
  [keyword: string]: unknown;
}

export interface QueryParam {
  name: string;
  description: string;
  schema: Schema;
}

export interface Operation {
  id: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  tag: string;
  summary: string;
  description: string;
  pathParams: string[];
  query: QueryParam[];
  body?: Schema;
  bodyRequired: boolean;
  response?: Schema;
}

export interface Resource {
  key: string;
  tag: string;
  title: string;
  label: string;
  scope: "global" | "workspace";
  list: string;
  listField?: string;
  item: Schema;
  idField: string;
  idParam?: string;
  create?: string;
  replace?: string;
  get?: string;
  update?: string;
  remove?: string;
  itemActions: string[];
  collectionActions: string[];
}

export interface Meta {
  title: string;
  version: string;
  operations: Record<string, Operation>;
  resources: Resource[];
  singletons: string[];
}
