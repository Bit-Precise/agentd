-- ACME (autocert) cache for agentserver's own certificate, so replicas share
-- it and pods stay stateless. Values are sealed by the keybox.
CREATE TABLE autocert_cache (
    key        text PRIMARY KEY,
    data       bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
