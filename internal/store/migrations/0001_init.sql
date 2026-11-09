-- agentserver state (design 4.1, 5.7). Private keys are encrypted by the
-- application (keybox) before they reach these columns.

CREATE TABLE server_state (
    id          int PRIMARY KEY CHECK (id = 1),
    private_key bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ca (
    id       int PRIMARY KEY CHECK (id = 1),
    cert_pem bytea NOT NULL,
    key_pem  bytea NOT NULL
);

CREATE TABLE relays (
    name       text PRIMARY KEY,
    public_key bytea NOT NULL UNIQUE,
    url        text NOT NULL,
    transports jsonb NOT NULL DEFAULT '{}',
    stun       text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz
);

CREATE TABLE relay_tokens (
    id         text PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz
);

CREATE TABLE workspaces (
    name              text PRIMARY KEY,
    base_domain       text NOT NULL UNIQUE,
    private_key       bytea NOT NULL,
    public_key        bytea NOT NULL UNIQUE,
    relay             text NOT NULL REFERENCES relays(name),
    dns_provider      text NOT NULL DEFAULT '',
    publish_dns       boolean NOT NULL DEFAULT false,
    routes_version    bigint NOT NULL DEFAULT 1,
    routes_default    text NOT NULL DEFAULT 'direct',
    directory_version bigint NOT NULL DEFAULT 1,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE join_tokens (
    id         text PRIMARY KEY,
    workspace  text NOT NULL REFERENCES workspaces(name) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    name       text NOT NULL DEFAULT '',
    roles      text[] NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz
);

CREATE TABLE nodes (
    workspace         text NOT NULL REFERENCES workspaces(name) ON DELETE CASCADE,
    name              text NOT NULL,
    public_key        bytea NOT NULL UNIQUE,
    role_caps         text[] NOT NULL DEFAULT '{}',
    joined_at         timestamptz NOT NULL DEFAULT now(),
    last_seen         timestamptz,
    handshake_ts      bytea,
    policy_sources    jsonb NOT NULL DEFAULT '{}',
    advertised_policy bytea,
    executor          bytea,
    p2p_enabled       boolean NOT NULL DEFAULT false,
    policy_version    bigint NOT NULL DEFAULT 0,
    policy_hash       bytea,
    policy_applied    bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace, name)
);

CREATE TABLE groups (
    workspace   text NOT NULL REFERENCES workspaces(name) ON DELETE CASCADE,
    name        text NOT NULL,
    private_key bytea NOT NULL,
    public_key  bytea NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace, name)
);

CREATE TABLE group_members (
    workspace  text NOT NULL,
    group_name text NOT NULL,
    node_name  text NOT NULL,
    PRIMARY KEY (workspace, group_name, node_name),
    FOREIGN KEY (workspace, group_name) REFERENCES groups(workspace, name) ON DELETE CASCADE,
    FOREIGN KEY (workspace, node_name) REFERENCES nodes(workspace, name) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE routes (
    workspace    text NOT NULL REFERENCES workspaces(name) ON DELETE CASCADE,
    id           text NOT NULL,
    position     int NOT NULL,
    from_subject text NOT NULL,
    protos       text[] NOT NULL DEFAULT '{}',
    domains      jsonb NOT NULL,
    to_target    text NOT NULL,
    PRIMARY KEY (workspace, id)
);

CREATE TABLE policies (
    workspace text NOT NULL REFERENCES workspaces(name) ON DELETE CASCADE,
    id        text NOT NULL,
    position  int NOT NULL,
    statement jsonb NOT NULL,
    PRIMARY KEY (workspace, id)
);

CREATE TABLE services (
    workspace  text NOT NULL,
    name       text NOT NULL,
    node_name  text NOT NULL,
    proto      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace, name),
    FOREIGN KEY (workspace, node_name) REFERENCES nodes(workspace, name) ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE TABLE certs (
    workspace      text PRIMARY KEY REFERENCES workspaces(name) ON DELETE CASCADE,
    state          text NOT NULL DEFAULT 'pending',
    cert_chain_pem bytea,
    key_pem        bytea,
    not_before     timestamptz,
    not_after      timestamptz,
    issuer         text NOT NULL DEFAULT '',
    last_error     text NOT NULL DEFAULT '',
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE revocations (
    workspace text NOT NULL REFERENCES workspaces(name) ON DELETE CASCADE,
    member    bytea NOT NULL,
    issuer    bytea NOT NULL,
    until_at  timestamptz NOT NULL,
    PRIMARY KEY (workspace, member, issuer)
);
