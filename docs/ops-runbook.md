# fusion-identity Operations Runbook

Operational procedures for running fusion-identity in production. Scope: backup/restore, monitoring + alerting, SLO targets, key rotation (KEK + service token), and on-call escalation. Honest about which items depend on infrastructure outside this service.

fusion-identity is the **sole JWT issuer** and tenant registry. Outage = all Fusion services cannot authenticate. Treat as Tier-1.

## Service posture

- Binds **127.0.0.1 only** (PRD C8). The gateway fronts it; no direct external exposure.
- REST on `11470`, gRPC `IdentityService` on `50051` (only when `FUSION_IDENTITY_REDIS_URL` set).
- **Fail-closed**: missing required env, invalid/expired token, missing membership, missing tenant_id → 401 or refuse to start. No default-tenant degradation.
- Two backends: `InMemoryStore` (dev/test default) or `PgStore` (production — inject via `FUSION_IDENTITY_USE_PGSTORE=1` + `FUSION_IDENTITY_DATABASE_URL`). Production MUST use PgStore.
- Postgres DB `fusion_tenant`, schema in `deploy/sql/schema.sql`, 9 tables.

## Health endpoints

- `GET /health` — liveness (process up). No auth.
- `GET /ready` — readiness (store connected, schema present). No auth.
- `GET /metrics` — Prometheus text, no auth. Tenant/user/member/key/audit/refresh gauges + auth/rpc/latency/token/quota counters.

## SLO targets

| SLO | Target | Measurement |
|-----|--------|-------------|
| Availability (REST auth path) | 99.9% monthly | `uptime` on `/ready` probes |
| Login latency p99 | < 200 ms | `rpc_latency_seconds` / http server logs |
| Token verify latency p99 | < 50 ms | `/api/v1/auth/verify` |
| gRPC `AuthorizeAndAcquire` p99 | < 30 ms | `rpc_latency_seconds{grpc_method="AuthorizeAndAcquire"}` |
| Audit append latency p99 | < 100 ms | store logs |
| Backup RPO | ≤ 5 min | PITR archive lag |
| Backup RTO | ≤ 15 min | restore drill (quarterly) |

These targets assume a single Postgres primary + Redis on the same host. HA Postgres (streaming replica + automatic failover) is an **infrastructure prerequisite** not delivered by this service — see "HA prerequisites" below.

## Backup and restore

### Database (fusion_tenant) — the source of truth

All tenant state, users, memberships, API keys, quotas, audit, usage, jti ledgers, refresh tokens live in Postgres. The service holds no durable state outside Postgres (Redis is cache + concurrency only — rebuildable).

**Logical backup (pg_dump) — daily snapshot:**
```bash
pg_dump -Fc -Z 6 -f /var/backups/fusion_tenant_$(date +%F).dump \
    "postgresql://fusion_identity_app:$PASS@127.0.0.1:5432/fusion_tenant"
# retain 14 days; verify restore into a scratch DB weekly
```

**Point-in-time recovery (PITR) — for RPO ≤ 5 min:**
Configure Postgres WAL archiving (`archive_mode=on`, `archive_command` to durable storage). Restore to a target timestamp with `pg_basebackup` + WAL replay. This is the primary recovery path for accidental `DELETE`/`UPDATE`.

**Restore procedure:**
1. Stop identity service: `./start.sh stop`
2. Restore DB to target point (pg_restore for dump, or PITR for WAL):
   ```bash
   createdb fusion_tenant_restore
   pg_restore -d fusion_tenant_restore /var/backups/fusion_tenant_YYYY-MM-DD.dump
   ```
3. Validate row counts + audit chain integrity:
   ```sql
   SELECT count(*) FROM tenants; SELECT count(*) FROM audit_log;
   -- chain integrity is enforced by the service's verify_audit_chain(); for
   -- a manual check, call the store method or compare prev_hash linkage.
   ```
4. Repoint `FUSION_IDENTITY_DATABASE_URL` at the restored DB (or rename), restart:
   `./start.sh start`
5. Verify `/ready` returns 200 and a sample login works.
6. **Post-restore audit**: record the restore event in the operator log. Restoring roll BACK the audit log to the restore point — entries after the target timestamp are lost. Document this in the incident report.

### Redis (cache + concurrency) — NOT backed up

Redis holds: api-key→tenant cache, tenant cache, daily quota counters, active concurrency leases. All are **rebuildable** from Postgres:
- api-key cache: repopulated on first authorize call (miss → store lookup → cache fill).
- tenant cache: same, on first tenant lookup.
- daily quota counters: **reset to 0 on Redis loss** — the service recomputes from `usage_ledger` on next `remaining_quota` query. A brief window of over-allow is possible (up to the quota TTL). Acceptable; not a correctness violation (quota is best-effort guard, not hard limit).
- active concurrency leases: **lost on Redis loss** — in-flight leases are forgotten. The `lease:{id}` keys expire on their own TTL; counters reset. A brief over-concurrency window is possible until leases naturally expire.

**Action on Redis loss**: restart Redis (or let the service reconnect). No restore needed. Monitor `auth_requests_total{status="quota_denied"}` for anomaly.

### Key material — backed up separately

- `FUSION_IDENTITY_JWT_KEY` (HS256) / RS256 private key PEM — backing up = storing the secret in a secrets manager (Vault, AWS SM, 1Password). Loss = all issued tokens unverifiable until rotation.
- `FUSION_IDENTITY_KEK` — same. Loss = all IdP `client_secret` + MFA `secret` undecryptable. MUST be backed up.
- `FUSION_IDENTITY_SERVICE_TOKEN` — shared with downstream verifiers. Loss = `/verify` callers must be reconfigured.

Store all three in the secrets manager with access logging. Never in the DB backup plaintext.

## Monitoring and alerting

Scrape `GET /metrics` (Prometheus). Recommended alert rules (Alertmanager):

```yaml
groups:
  - name: fusion-identity
    rules:
      - alert: IdentityDown
        expr: up{job="fusion-identity"} == 0
        for: 1m
        labels: { severity: page }
        annotations: { summary: "fusion-identity unreachable" }

      - alert: IdentityNotReady
        expr: kube_ready_check or ready_probe == 0
        for: 2m
        labels: { severity: page }
        annotations: { summary: "fusion-identity /ready failing" }

      - alert: IdentityAuthErrorSpike
        expr: rate(auth_requests_total{status_code=~"401|403"}[5m]) > 10
        for: 5m
        labels: { severity: page }
        annotations: { summary: "auth 401/403 spike — possible token storm or key drift" }

      - alert: IdentityQuotaDenialSpike
        expr: rate(auth_requests_total{status="quota_denied"}[5m]) > 50
        for: 10m
        labels: { severity: warn }
        annotations: { summary: "quota denials rising — tenant may be over limit or Redis quota lost" }

      - alert: IdentityRpcLatencyHigh
        expr: histogram_quantile(0.99, rate(rpc_latency_seconds_bucket[5m])) > 0.05
        for: 5m
        labels: { severity: warn }
        annotations: { summary: "gRPC p99 latency > 50ms" }

      - alert: IdentityTokensConsumedNoQuota
        expr: quota_remaining == 0
        for: 10m
        labels: { severity: warn }
        annotations: { summary: "tenant exhausted daily quota" }

      - alert: IdentityPrevTokenStillUsed
        # D3: service token rotation grace — prev token accepted. Should drop to
        # zero after rotation. Persisting means a caller wasn't rotated off.
        expr: increases(log_messages{level="WARNING",msg=~".*PREV token.*"}[1h]) > 0
        for: 30m
        labels: { severity: warn }
        annotations: { summary: "service token PREV still in use — finish rotation" }
```

Log-based alerts (structured JSON, `FUSION_IDENTITY_LOG_JSON=1`):
- `pgstore: connected as a superuser — RLS BYPASSED` → **page**: production must connect as `fusion_identity_app`, not superuser. RLS is bypassed otherwise (red-line #3 weakened).
- `decrypt_secret: ok (prev kek grace)` → **warn**: KEK rotation not yet swept (D2). Run `POST /api/v1/admin/kek/reencrypt`.
- `require_service_token: accepted via PREV token` → **warn**: D3 rotation window still open.
- `cross-tenant blocked` → **info**: normal enforcement; spike = probe attempt.

## Key rotation

### KEK rotation (D2) — encrypts IdP client_secret + MFA secret

Dual-window, zero-downtime. The KEK encrypts at-rest secrets; rotation re-encrypts all blobs to the new key without taking the service down.

1. **Generate new KEK**: `openssl rand -hex 32`
2. **Set both env, restart** — new key as primary, old as grace window:
   ```bash
   export FUSION_IDENTITY_KEK="$(openssl rand -hex 32)"          # NEW
   export FUSION_IDENTITY_KEK_PREV="<old-kek-value>"             # OLD
   ./start.sh restart
   ```
   During the window: secrets encrypted under the OLD key decrypt via `kek_prev`; new writes encrypt under the NEW key. Config rejects `KEK_PREV == KEK` or `KEK_PREV == JWT_KEY` (isolation).
3. **Sweep — re-encrypt all secrets to the new key** (service token, `_system` tenant):
   ```bash
   curl -X POST http://127.0.0.1:11470/api/v1/admin/kek/reencrypt \
        -H "Authorization: Bearer $FUSION_IDENTITY_SERVICE_TOKEN" \
        -H "X-Tenant-Id: _system"
   ```
   Returns `{"idps": {...}, "mfa": {...}, "next_step": "drop FUSION_IDENTITY_KEK_PREV..."}`.
   - `migrated` = re-encrypted; `failed` = couldn't decrypt under prev (likely already on new key — investigate if unexpected); `skipped` = no secret blob.
4. **Close the window — drop PREV, restart**:
   ```bash
   unset FUSION_IDENTITY_KEK_PREV
   ./start.sh restart
   ```
5. **Verify**: trigger an OIDC login (decrypts IdP secret) + an MFA login (decrypts MFA secret). Both must succeed under the new key alone. Confirm no `prev kek grace` warnings in logs.

**Rollback**: if the sweep fails, keep `KEK_PREV` set — secrets still decrypt. Investigate `failed` count before closing the window. Do NOT drop PREV until `migrated + skipped == total` and logins verify.

### Service token rotation (D3) — gates /verify + admin + SCIM + usage emit

Dual-window so downstream callers rotate without a hard cutover.

1. **Generate new token**: `openssl rand -hex 24` (≥ 24 bytes).
2. **Set both env, restart**:
   ```bash
   export FUSION_IDENTITY_SERVICE_TOKEN="$(openssl rand -hex 24)"   # NEW
   export FUSION_IDENTITY_SERVICE_TOKEN_PREV="<old-token>"          # OLD
   ./start.sh restart
   ```
   Both tokens accepted during the window (constant-time compared). Config rejects `PREV == current` or PREV shorter than 24 bytes.
3. **Rotate callers off the old token**: update each downstream verifier (gateway, services calling `/verify`, SCIM clients, usage emitters) to the NEW token, one at a time. Each switch is non-disruptive — the old token still works for any not-yet-rotated caller.
4. **Monitor**: watch logs for `accepted via PREV token`. When that warning stops, all callers are on the new token.
5. **Close the window**:
   ```bash
   unset FUSION_IDENTITY_SERVICE_TOKEN_PREV
   ./start.sh restart
   ```
6. **Verify**: a call with the OLD token → 401; a call with the NEW token → 200.

### JWT signing key rotation

HS256: change `FUSION_IDENTITY_JWT_KEY` and restart. All previously issued tokens become unverifiable (no grace window for HS256). For zero-downtime, rotate during a low-traffic window and accept forced re-login, OR migrate to RS256 (JWKS + `kid` with 24h retired-key grace — see `/.well-known/jwks.json`).

RS256: keys rotate via the keyring (`FUSION_IDENTITY_JWT_KEYRING_PATH`); retired keys verify for 24h. No restart needed for verification; new tokens sign with the active kid.

## HA prerequisites (infrastructure, not this service)

D4 tests prove **state consistency across two service instances sharing one Postgres** — tenant visibility, jti issuance/revocation, audit chain, usage aggregation all span instances. This service is HA-safe at the application layer. **But HA also requires:**

- **Postgres HA** — streaming replication + automatic failover (Patroni, Stolon, or managed RDS/CloudSQL). Single Postgres is a SPOF. This service does not manage replication; the operator must.
- **Redis HA** (if the gRPC/concurrency plane is used) — Redis Sentinel or Redis Cluster. Redis loss is non-fatal (cache rebuilds, leases expire) but concurrency limits reset.
- **Stateless service instances** — run ≥ 2 behind the gateway; the gateway health-checks `/ready`. No session affinity needed (all state is in Postgres/Redis).
- **Connection pool sizing** — each instance opens `FUSION_IDENTITY_DB_POOL_MAX` (default 8) connections. Size Postgres `max_connections` for `instances × pool_max + headroom`.

External load testing and penetration testing are separate engagements — file tracking issues, do not block release on this service's code.

## On-call escalation

1. **Check `/ready`** — if down, check Postgres connectivity first (`FUSION_IDENTITY_DATABASE_URL`), then process logs (`./start.sh log`).
2. **Auth storm (401/403 spike)** — check for JWT key drift (a verifier using a stale key), token clock skew, or a misconfigured service token. Logs tag `tenant_id`/`user_id`.
3. **Quota denial spike** — check Redis health (quota counters may have reset); check whether a tenant genuinely exceeded limits (`GET /api/v1/admin/tenants/{id}/quota`).
4. **Audit chain break** — `verify_audit_chain` returns `valid: false` → possible tampering or a concurrent-append bug. Page security; preserve the DB snapshot before further writes.
5. **RLS bypass warning** — `connected as a superuser` in logs → production connected as superuser, RLS not binding. Fix the connection role to `fusion_identity_app` immediately (red-line #3).
6. **KEK decrypt failure** — `ciphertext authentication failed` → either KEK drifted or a blob is corrupted. Do NOT drop `KEK_PREV` if rotation is in flight. Restore the secret from the secrets manager if the KEK itself was lost.

## Incident response postmortem template

- Summary / impact (tenants affected, duration)
- Timeline (detect → mitigate → resolve)
- Root cause
- What broke in monitoring (alert that should have fired but didn't)
- Action items (owner + due date)
- Add the incident to the audit log narrative (the audit_log itself is immutable; this is an external doc)
