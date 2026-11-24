-- 0026_messaging.sql — Issue #109: tenant-scoped conversation threads for the
-- factory ticket flow (customer <-> operator, unblocks fusion-web-shell#186).
-- Wire contract frozen by the shell-side parsers (fusion-web-shell#187):
--   GET/POST /api/messaging/conversations, GET/POST .../{id}/messages,
--   PATCH .../{id} (status chip + linked issue id, operator only).
-- Status chips are stored VERBATIM (client degrades unknown values to 'open').

CREATE TABLE IF NOT EXISTS conversations (
    id              TEXT        PRIMARY KEY,
    tenant_id       TEXT        NOT NULL REFERENCES tenants(tenant_id),
    scope           TEXT        NOT NULL DEFAULT 'factory_order',
    ref             TEXT        NOT NULL DEFAULT '',
    subject         TEXT        NOT NULL DEFAULT '',
    status          TEXT        NOT NULL DEFAULT 'open',
    linked_issue_id TEXT        NOT NULL DEFAULT '',
    created_by      TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_conversations_tenant_updated
    ON conversations(tenant_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_conversations_tenant_ref
    ON conversations(tenant_id, scope, ref);

CREATE TABLE IF NOT EXISTS messages (
    id              BIGSERIAL   PRIMARY KEY,
    conversation_id TEXT        NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    tenant_id       TEXT        NOT NULL REFERENCES tenants(tenant_id),
    sender          TEXT        NOT NULL,
    sender_role     TEXT        NOT NULL CHECK (sender_role IN ('customer', 'operator', 'system')),
    content         TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_messages_conv_id ON messages(conversation_id, id);

CREATE TABLE IF NOT EXISTS conversation_reads (
    conversation_id TEXT   NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id         TEXT   NOT NULL,
    last_read_id    BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (conversation_id, user_id)
);
