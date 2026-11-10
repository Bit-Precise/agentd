-- The DNS provider of a workspace follows from its base domain
-- (dns_providers[].zones in the agentserver configuration).
ALTER TABLE workspaces DROP COLUMN dns_provider;
