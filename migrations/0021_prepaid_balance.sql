-- Issue #74: prepaid balance & recharge plane.
-- Balance is DERIVED from balance_ledger (sum of deltas) — no balance column
-- to drift. Currency conversion happens at the payment layer; every amount
-- here is tokens.
CREATE TABLE IF NOT EXISTS prepaid_orders (
    order_id      TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    tokens        BIGINT NOT NULL CHECK (tokens > 0),
    promo_tokens  BIGINT NOT NULL DEFAULT 0 CHECK (promo_tokens >= 0),
    status        TEXT NOT NULL DEFAULT 'created'
                  CHECK (status IN ('created', 'paid', 'cancelled')),
    provider      TEXT NOT NULL,
    provider_ref  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    paid_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_prepaid_orders_tenant
    ON prepaid_orders(tenant_id, created_at);

CREATE TABLE IF NOT EXISTS balance_ledger (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    delta       BIGINT NOT NULL,
    reason      TEXT NOT NULL,
    ref_id      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_balance_ledger_tenant
    ON balance_ledger(tenant_id, id);
