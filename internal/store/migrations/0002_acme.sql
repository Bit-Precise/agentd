-- ACME accounts used for workspace wildcard certificates (keys sealed by the keybox).
CREATE TABLE acme_accounts (
    id         text PRIMARY KEY,          -- "<directory url>|<email>"
    key_pem    bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
