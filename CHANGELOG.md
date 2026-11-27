---
doc_id: fusion-identity/changelog
product: fusion-identity
class: core
entry: service
doc_type: changelog
title: { zh: "fusion-identity 变更日志", en: "fusion-identity changelog" }
audience: engineer
status: draft
version: 0.2.48
updated: 2026-11-27
owner: "@dahai"
source_of_truth:
  - pyproject.toml
  - README.md
---

# Changelog

## 0.2.48

### Issue #115 — dev log-also fallback for verification links (SMTP-configured dev machines)
- **What**: `fusion_identity/email_sender.py` — when `FUSION_IDENTITY_ENV` is empty (development) and SMTP is configured, verification/reset links are ALSO WARNING-logged alongside SMTP delivery, on both the send-success path (`dev log-also`) and the delivery-failure path; production (`FUSION_IDENTITY_ENV=production`) stays strictly send-only, links never logged.
- **Why**: a dev machine with supervisor-injected SMTP (e.g. `smtp.qq.com`) registering a non-receivable test address lost the verification token silently — SMTP was configured so the dev log fallback never fired, and the relay bounced on an undeliverable domain with no operator signal.
- **Test-domain flag**: reserved undeliverable domains (`example.com`, `example.org`, `example.net`, `test.local`) get a loud "cannot receive mail" WARNING on every send in any mode — bounce-flag, not a hard reject, so registration behavior is unchanged.
- **Tests**: `tests/test_email_log_also_issue115.py` (5 offline cases, SMTP relay stubbed — dev+SMTP logs the link, prod never does, example-domain WARNING in both modes).

## 0.2.47

### Issue #111 — service-token SSO ticket minting for named users
- **What**: `POST /api/v1/auth/ticket/service` (service-token gated, tenant-middleware-exempt, rate-limited) mints a one-time `fsso_` ticket bound to `{user_id, tenant_id}` — reusable of the #48 single-use ticket store and exchange, no new dependencies, no migration.
- **Why**: closes the gateway#715 local-password gap — a shell session issued by the gateway's own user store has no identity principal, and no existing primitive could mint a user bearer for one (service accounts are `role=service`, `/auth/ticket` requires a bearer, the gateway never holds the password). The gateway now translates any shell session whose sub/tenant maps to a real member into a real user bearer via the #48 exchange.
- **Fail-closed**: same predicate as `exchange_sso_ticket` — user active (not disabled/locked), tenant active, membership present. Unknown user / inactive tenant / non-member → uniform 404 (service plane is operator-facing, no enumeration concern).
- **Audit**: distinct impersonation-class action `auth.ticket_issued.service` with role `service` (non-human actor, same convention as messaging sender_role) — grep-able separately from self-minted `auth.ticket_issued`. Raw ticket never lands in the audit trail.
- **Tests**: `tests/test_service_ticket_issue111.py` (7 offline: roundtrip + exchange → real member bearer, service-token required — plain bearer 401 too, unknown user / non-member / disabled user / suspended tenant 404, single-use replay 401, audit action) + `test_pg_service_ticket_mint_roundtrip` (PG: hash-at-rest row, exchange, replay 401, audit row).

## 0.2.46

### Issue #112 — refresh rotation 500: `replaced_by` FK violated (rotate before insert)
- **Root cause**: `auth.py` refresh flow ordered the writes wrong — `rotate_refresh_token(jti, nrjti)` set `refresh_tokens.replaced_by = nrjti` BEFORE the new refresh row existed, violating the `refresh_tokens_replaced_by_fkey` FK on PG (`Key (replaced_by)=(…) is not present in table "refresh_tokens"`) → 500 on EVERY rotation. InMemoryStore has no FK, so offline tests were blind (the recurring #39/#40 class).
- **Fix** (`auth.py`): insert the new refresh row FIRST, then rotate the old one. F7 CAS semantics unchanged — `rotate_refresh_token` still fails closed when the old jti is no longer `active`; on CAS loss the whole family is revoked, INCLUDING the row just inserted (same `family_id`), so reuse detection still kills the chain.
- **Regression test** (`tests/test_refresh_integration.py`, PG): full HTTP login → refresh → refresh chain, then replay of the first refresh token → 401 + family-wide revocation verified in the DB. Without the fix it reproduces the exact `ForeignKeyViolationError`.
- Unblocks the gateway session→identity messaging bridge (fusion-gateway#715 / PR #716) and fusion-web-shell#186.

## 0.2.45

### Fix — migration runner grants + probes `REFERENCES` (issue #109 follow-up)
- **Root cause (prod incident)**: migration `0026_messaging.sql` creates `conversations` with an FK to `tenants`; creating an FK requires `REFERENCES` on the referenced table. The migration runner only granted + probed the 4 DML privileges (issues #94/#96), so on prod (runner connects AS `fusion_identity_app`) startup 500'd with `permission denied for table tenants`, crash-looping the login plane.
- **Fix** (`migrations.py`, `deploy/sql/ensure-grants.sql`): `GRANT ... REFERENCES` added to the runner grant, default privileges, the error-message hint, and the operator backstop script; the fail-closed privilege probe now checks all 5 privileges — a missing `REFERENCES` aborts startup with the same table:privilege report.
- Operator one-time fix on existing installs: `sudo -u postgres psql -d fusion_identity -f deploy/sql/ensure-grants.sql`.
- No schema change; no new tests (probe behavior pinned by the #94/#96 suite, all green).

## 0.2.44

### Issue #109 — Messaging service: `/api/messaging` conversation threads
- **What**: tenant-scoped operator↔customer ticket threads (factory-order scope), server owner per architecture ruling 2026-11-24 — unblocks fusion-web-shell#186.
- **Wire contract** (frozen by the shell parsers `apps/shell/src/lib/messaging.ts`): GET/POST `/conversations`, GET/POST `/conversations/{id}/messages?after=`, PATCH `/conversations/{id}` (operator only). Snake_case fields, epoch-float timestamps, hyphenated status chips stored VERBATIM (`open|triaged|in-progress|fixed|awaiting-customer|closed`; client degrades unknown → `open`).
- **Auth model**: user-scoped tenant resolution — the shell sends NO `X-Tenant-Id`; `_OidcContextMiddleware` extended to inject `x-tenant-id` from the bearer's `tid` claim for `/api/messaging/` paths (unverified local decode for context only; tenant middleware + `require_bearer` still fully verify; no valid token → no injection → 401 fail-closed). Roles `tenant_admin`/`operator` see all tenant threads and set the status chip; other roles see only threads they opened (cross-user access 403). `sender_role`: admin/operator→`operator`, `service`→`system`, else `customer`.
- **Storage** (migration `0026_messaging.sql`): `conversations` (TEXT id, tenant FK, scope/ref/subject/status/linked_issue_id), `messages` (BIGSERIAL — `?after=` is a numeric id filter, tenant FK, sender_role CHECK), `conversation_reads` (per-user read markers, GREATEST semantics). `deploy/sql/schema.sql` regenerated from migrations (issue #105 process; 36 tables). Unread = messages id > read marker AND sender ≠ viewer.
- **Known upstream gap**: fusion-gateway has no `prefix: /api/messaging` route to identity yet — config-only change in the gateway repo (issue filed upstream); direct `:11470` calls work today.
- Tests: 8 offline (`tests/test_messaging_issue109.py` — role visibility, unread clearing, after-filter + non-numeric degrade, cross-user 403, operator-only PATCH verbatim status, middleware fail-closed, InMemory store roundtrip) + 1 integration (`tests/test_messaging_integration.py` — PgStore roundtrip incl. TIMESTAMPTZ epoch normalize, dynamic WHERE, GREATEST read markers).

## 0.2.43

### Issue #107 — JWT keyring persisted at startup; kid stable across restarts
- **Root cause**: `FUSION_IDENTITY_JWT_KEYRING_PATH` was only consumed on `rotate()` / `prune()` — a freshly generated RS256 key was never written, so the file stayed absent and EVERY restart rolled a new keypair (new kid), invalidating all outstanding tokens and breaking gateway/commerce JWKS caches until refetch. Prod logs confirmed the kid changed exactly at each restart (no live rotation had occurred).
- **Fix** (`jwks.py`): the keyring is persisted IMMEDIATELY after initial RS256 generation (and still on rotation/prune). Restart recovers the persisted keypair — `kid` unchanged. Initial persist failure now REFUSES the start (fail-closed, consistent with red line #1: an unpersisted key is guaranteed token invalidation on the next restart). Persist file written 0600 via atomic tmp+rename. HS256 unchanged.
- **Rotation story (documented)**: rotation retires the current kid with a 24h verification grace window (published in `/.well-known/jwks.json` until pruned); the full current+retired history survives restarts via the persist file.
- Tests: 6 offline (`tests/test_jwks_persist_issue107.py` — immediate persist + 0600 perms, same kid across restart, rotation survives restart with old kid verifiable, persist failure refuses start, HS256 never persists, corrupt file falls back to fresh with WARNING).

## 0.2.42

### Issue #105 — `deploy/sql/schema.sql` regenerated from migrations; drift-guard tests
- **Root cause**: `schema.sql` was hand-maintained and had drifted from the migration chain — missing the `audit_seq_seq` sequence, the `service_accounts` / `prepaid_orders` / `balance_ledger` tables (issues #28/#74), the `users_username_uniq` UNIQUE index (#83), the 0007 RLS policies, and the `roles` / `plan_templates` seed rows. A fresh DB from the documented operator flow failed 22 integration tests.
- **Fix**: `schema.sql` is now GENERATED — a `pg_dump --schema-only --no-owner --no-privileges` of a migrations-only build (0001→0025), plus a re-appended SEED DATA block mirroring migrations 0001 (`roles`) and 0010 (`plan_templates`) that `--schema-only` drops. Header declares the file generated, points at the regeneration recipe, and says DO NOT hand-edit. `migrations/` stays the single source of truth for DDL.
- **Drift guard**: new `tests/test_schema_drift_issue105.py` (5 offline tests) — generated-header presence, the exact objects from the drift report, seed rows vs migration 0010, CREATE TABLE set vs migrations, RLS-policy set vs migrations. A future migration without regenerating `schema.sql` fails CI offline.
- **Acceptance**: fresh DB built from the regenerated `schema.sql` + pre-marked `schema_migrations` passes the full integration suite (66 tests, verified on Postgres 16).

## 0.2.41

### Issue #103 — email delivery mode made observable; prod refuses the silent logged fallback
- **/health now reports the email mode**: identity owns its liveness probe (`routes/health.py`, `create_app(..., enable_health=False)`) and returns the fusion_core shape plus `email: "smtp" | "logged"` (helper `email_sender.email_mode`). Monitoring can alert on `logged` — the silent dev fallback that caused the 2026-11-19 prod incident (registration 201 with the verification link only in a WARNING log line, root cause: prod env had no `FUSION_IDENTITY_SMTP_*` vars).
- **Fail-closed prod marker**: new `FUSION_IDENTITY_ENV` (default empty = development). `FUSION_IDENTITY_ENV=production` with `FUSION_IDENTITY_SMTP_HOST` unset raises `ConfigError` at startup — a prod deploy cannot silently run the logged-email fallback (red line #1). Development keeps the logged fallback untouched.
- Tests: 6 offline (`tests/test_email_mode_issue103.py` — health shape + both modes, helper, prod-without-SMTP refuses start, prod-with-SMTP starts, dev defaults unchanged).

## 0.2.40

### Issues #99 + #101 — ops event emission (flywheel Loop A) + per-user data-reflow opt-out
- **Ops event plane** (issue #99): new `ops_events.py` — desensitized telemetry helpers over `fusion_core.ops.OpsEmitter`. Enabled only when `FUSION_IDENTITY_OPS_DSN` is set (default off — zero extra I/O); fail-open (an ops outage logs and continues, auth never blocked). Payload hygiene is a hard rule and is test-grepped: user/tenant ids appear ONLY as `sha256("identity:{id}")[:16]` with `u:`/`t:` prefixes; no raw emails, usernames, JWTs, or passwords in any payload; login-failure events carry NO user id so the ops DB cannot become an account-existence oracle.
- **Emission points**: login success (with latency) / failure; token issued (`kind=refresh|sso|service`) on refresh, SSO ticket exchange, and service-account login; api-key token counters on gRPC `ReportUsage`; hourly tenant/user totals piggybacked on the retention sweep tick (`auth.tenant.stats` — counters only, no ids).
- **Data-reflow opt-out** (issue #101): migration `0025` adds `users.data_reflow_enabled BOOLEAN NOT NULL DEFAULT TRUE` (both store backends + `deploy/sql/schema.sql`). New user-scoped settings plane `GET/PUT /api/v1/auth/settings` (tenant-middleware-exempt, bearer-gated; PUT audits `auth.settings_updated`); the `true→false` transition emits `auth.data_reflow.optout` (hashed ids) as the purge/anonymize signal — the purge itself lives in the ops pipeline (fusion-ops), identity stores no prompt text at all. Service-plane batch lookup `POST /api/v1/admin/data-reflow/flags` (`{user_ids}` ≤500 → `{flags}`) for the ops pipeline; missing users read `true`.
- Tests: 12 offline (`tests/test_ops_reflow_issue99.py` — hashing determinism, settings roundtrip, opt-out event only on the false transition, batch flags, login success/failure emission, refresh `kind`, payload-hygiene grep for raw secrets, no-emitter no-op, broken-emitter fail-open, retention stats emit) + 3 PG integration (`tests/test_ops_pg_issue99.py` — migration 0025 column shape, flag persist + batch flags, unknown-user defaults).

## 0.2.39

### Issue #98 — password-reset hardening: enumeration, token, abuse controls
- **Timing oracle closed**: reset-email delivery moved to a fire-and-forget asyncio task (`_spawn_reset_email`, hard-referenced task set) — the hit path no longer waits on a slow SMTP round-trip, so existing and non-existing accounts answer with indistinguishable latency. The explicit-reveal operator mode (`FUSION_IDENTITY_PASSWORD_FORGOT_REVEAL_MISSING`) keeps synchronous delivery because its 502 is an intentional existence signal.
- **Exponential backoff abuse gate** (`ResetBackoff` in `ratelimit.py`): per-requested-account + per-IP cooldown keyed BEFORE any account lookup (throttling is identical for existing and non-existing accounts — no enumeration via the abuse gate), burst tolerance of 2 requests, then doubling delay capped at `FUSION_IDENTITY_RESET_BACKOFF_CAP` (default 300s); 429 carries `Retry-After`. Spike WARNING logged from the 4th rapid attempt; `FUSION_IDENTITY_RESET_BACKOFF_BASE` (default 2s, 0 disables). Doubles as the per-target mail-bombing gate — rotating IPs cannot re-arm the same address.
- **Token lifecycle**: password change via ANY path (`change_password`) now clears an outstanding reset token — new store method `clear_password_reset_token` on both backends (NULL both columns, idempotent, False on unknown user). Single-use atomic consume, 256-bit `token_urlsafe` token, sha256 at rest, TTL ≤ 30 min were already in place (#90) and are regression-covered.
- Tests: 9 offline (`tests/test_reset_hardening_issue98.py` — uniform response, sub-5s hit path under a 30s pending delivery, progressive Retry-After growth + spike log, per-account gate across rotating IPs, opt-out, single-use/expiry, change-password invalidation) + 1 PG integration (`tests/test_reset_pg_issue98.py`). Legacy reset tests updated to await the async delivery. Fixed a pre-existing test-pollution bug: `test_password_reset_integration.py` raw-assigned `email_sender.send_email` without restore.

## 0.2.38

### Issue #96 — privilege probe tightened to the full grant set
- Follow-up to #94: the startup probe only checked `SELECT`, but the login plane also INSERTs (`issued_jtis`, `audit_log`) — a table readable but not writable would still 500 prod while the probe passed.
- `assert_app_role_privileges` now probes `SELECT, INSERT, UPDATE, DELETE` on every user table and fails startup listing each missing `table:privilege` pair.
- Backfill audit of migrations 0001–0024: no per-migration GRANTs added — the convention stays the runner-level grant on every startup (the shared post-migration step allowed by the issue), which covers all tables regardless of which migration created them; `deploy/sql/ensure-grants.sql` remains the operator backstop for psql-applied migrations.
- PG integration tests: REVOKE of INSERT/UPDATE/DELETE on `users` each aborts startup; fresh-DB full migration run passes the tightened 4-privilege probe with no manual GRANTs (issue #96 acceptance).

## 0.2.37

### Issue #94 — migrations ship with app-role grants (login-plane 500 fix)
- Regression fixed: migration `0024` reached prod without the `fusion_identity_app` GRANT — every login 500'd (`permission denied for table account_deletions`) because the login plane consults the tombstone table while tests ran as superuser/owner.
- Migration runner (`fusion_identity/migrations.py`) now, on EVERY startup: best-effort `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO <app-role>` + `ALTER DEFAULT PRIVILEGES` (covers fresh installs and future migrations), then a fail-closed **privilege probe** — if the app role cannot SELECT any user table, startup aborts with a loud RuntimeError listing the tables.
- Role name via `FUSION_IDENTITY_APP_ROLE` (default `fusion_identity_app`); missing role → probe skipped with a warning.
- Operator backstop: `deploy/sql/ensure-grants.sql` (superuser GRANT + DO-block probe).
- PG integration tests: fresh-DB full migration run leaves every table readable by the app role (acceptance criterion), REVOKE → probe raises loudly, unknown role → noop.

## 0.2.36

### Issue #90 — password reset flow hardening
- `POST /api/v1/auth/password/reset-request` — first-class alias of `/password/forgot` (identical behavior, rate limit, audit); clients get a well-named endpoint.
- Reset token TTL default tightened to 1800s (30 minutes) — the token is a bearer capability that resets the password.
- Reset-request real hits are audited (`auth.password_reset_requested`); unknown emails stay enum-free with no audit row.
- Successful reset now emails a "your password was changed" confirmation (`send_password_reset_success_email`); delivery failures are logged, never fail the reset.

### Issue #91 — account deletion / export / retention
- New account plane `/api/v1/auth/account/*` (bearer, tenant-middleware-exempt, user-scoped): `POST /delete` (password re-confirm → 7d grace window, sessions revoked immediately), `DELETE /delete` (cancel), `GET /export` (`{profile, memberships, audit}`).
- Deletion gate in all 4 auth planes (login, bearer verification, gRPC authorize, refresh): pending deletion → `account is scheduled for deletion`.
- `RetentionWorker` background sweep: due purges (single PgStore transaction, audit tombstoned so the hash chain stays continuous), expired token-ledger pruning, audit pruning at `FUSION_IDENTITY_AUDIT_RETENTION_MONTHS` (default 12). All idempotent.
- Migration `0024_account_deletion.sql` — table `account_deletions` (29 tables total). Env: `FUSION_IDENTITY_DELETE_GRACE_SECONDS` (604800), `FUSION_IDENTITY_AUDIT_RETENTION_MONTHS` (12), `FUSION_IDENTITY_RETENTION_SWEEP_SECONDS` (3600).

## 0.2.35

### Added

- **PyPI distribution** — `pip install fusion-identity` now works from PyPI. `fusion-core>=0.12` (already published) added to dependencies; sdist + wheel built and published by the new `.github/workflows/release-packages.yml` (Trusted Publishing, no token secret; one-time pending-publisher registration on pypi.org required). `fusion-identity --version` added to the console entry.
- **Homebrew install** — formula `packaging/homebrew/fusion-identity.rb` installs a pre-built relocatable venv tarball (one per platform: darwin-arm64/darwin-x64/linux-x64/linux-arm64) from the GitHub release. Tarballs are built by `scripts/package-venv.sh` (`python -m venv --copies`; pyvenv.cfg + console-script shebangs rewritten at install time against Homebrew `python@3.12`; every artifact smoke-tested for relocation before upload). Formula is copied into the `dahai80/homebrew-fusion-mlx` tap on each release.

## 0.2.34

Current version (`pyproject.toml`).

- #83: username uniqueness enforced end-to-end. The register route's pre-check existed since #39, but the `users` table had no UNIQUE constraint on `username` (only `email` did) — two concurrent signups with the same username both passed the pre-check and both inserted, and login resolves usernames via a single-row lookup (login-hijack vector). Migration `0023` adds `users_username_uniq`; the raced insert now falls into the existing `StoreConflict` catch → 409 fallback. `InMemoryStore.create_user` mirrors the check. 409-on-taken-username remains a documented accepted risk (the issue explicitly requires 4xx)
- #84 (option 1, enum-free): duplicate-email registration with email verification ON is now a SILENT NO-OP — the response is byte-shape-identical to a fresh signup's 201 `{status:"verification_required"}` (throwaway user_id), nothing is persisted, and NO verification email is sent to the already-registered address (an emailed link for an address the attacker just probed would be worse than the oracle). Replaces the issue #53 readable 409, which was an account-existence oracle for the whole email base. Recovery path for legitimate owners is unchanged: the public `/verify-email/resend`. With verification OFF (dev-only mode) the 409 stays — the endpoint returns a live token pair for a NEW account, and issuing one for an existing account would be a takeover


## 0.2.33

Current version (`pyproject.toml`).

- #81: CI efficiency retrofit per dahai80/fusion#2 checklist — `concurrency: docs-${{ github.ref }}` with `cancel-in-progress: true` (superseded pushes no longer queue redundant validates). Dependency cache, sharding, and nightly tier assessed as not applicable: the only workflow job runs a stdlib-only validator in ~11s (setup-python `cache: pip` hard-fails when no pip install ever populates `~/.cache/pip`; the offline pytest suite is ~34s, far under the shard threshold; no CI-run tests need a nightly tier). No runtime code change.

## 0.2.32

Current version (`pyproject.toml`).

- #79: service-plane member enumeration + removal for operator purge/offboarding (motivated by gateway#642 probe-user cleanup, which previously had no supported path — the member plane needs a member JWT and the #35 summary is counts-only). `GET /api/v1/admin/tenants/{tid}/members?limit=&offset=` returns `{total, items:[{user_id, username, email, role, status, joined_at}]}` (`limit` 1–200 default 50; store method `admin_list_members` on both stores — PgStore LEFT JOINs users for username/status). `DELETE /api/v1/admin/tenants/{tid}/members/{user_id}` removes a membership with the same fail-closed pre-last-admin rule as the member plane (403 on the final `tenant_admin`), invalidates the tenant cache, and audits `member.remove` with role `service`; 404 on unknown tenant/member


All notable changes are tracked via GitHub releases and merged PRs. Version in `pyproject.toml` is the source of truth for the current release.

## 0.2.31

Current version (`pyproject.toml`).

- #76: headless service-account principal for acceptance suites / CI clients (owner verdict on fusion-site#37 — NO captcha backdoor). New `service_accounts` table (migration `0022`): tenant-pinned, `fsa_`-prefixed credential (sha256 at rest, raw returned exactly once), revocable, audit-logged. Admin plane (service-token gated): `POST/GET /api/v1/admin/tenants/{tid}/service-accounts`, `DELETE .../service-accounts/{id}` (audited `svc.created`/`svc.revoked`). Machine login: `POST /api/v1/auth/service-accounts/token` `{credential}` (tenant-middleware-exempt — the credential is the secret; rate-limited) → short-TTL ACCESS-only token (no refresh; machines re-exchange), role `service`, scopes from the account, TTL `FUSION_IDENTITY_SERVICE_ACCOUNT_TTL` default 900s
- #76: the shared authorization predicate (`_authorize`, `resolve_bearer_claims`, `/verify`) validates the service ACCOUNT (no users row, no membership) before the human gates and keeps the account's token scope — service tokens authenticate against every bearer-protected surface, read-only by construction (empty write classes + menus), audited `svc.token_issued` with role `service` so non-human sessions are distinguishable in the audit chain

## 0.2.30

- #74: prepaid balance & recharge plane. New tables `prepaid_orders` (order state machine `created → paid`, migration `0021_prepaid_balance.sql`) and `balance_ledger` (append-only; balance is always `SUM(delta)` — no balance column to drift). Currency conversion happens at the payment layer; identity only ever sees tokens
- #74: admin recharge API (service-token gated): `POST /api/v1/admin/tenants/{tid}/recharge/orders` (first paid order per tenant earns the first-purchase promo, `FUSION_IDENTITY_FIRST_PURCHASE_PROMO_PCT` default 20%, 0 disables), `GET .../recharge/orders`, `GET .../recharge/orders/{id}`, `POST .../recharge/orders/{id}/pay` (idempotent — the ledger credit fires only on the `created → paid` transition), `GET .../recharge/balance`. Payment provider pluggable via `FUSION_IDENTITY_PAYMENT_PROVIDER` (default `stub`; unknown values fail closed with 503). Audited `recharge.paid`
- #74: gRPC consumption model — the free daily quota (`tpm`) is consumed first; once exhausted, a positive prepaid balance covers the overflow. Authorize refuses `BALANCE_EXHAUSTED` (new enum value 8, HTTP-mapped 429) only when the daily quota is used up AND the balance is ≤ 0; `ReportUsage` debits exactly the tokens that crossed the daily limit (overflow delta, not the whole report) and returns the new `remaining_balance` field. Mid-session recharge takes effect on the next authorize (balance is read live, api keys unchanged)

## 0.2.29

- #71: the quota/api-key enforcement plane is ON by default — `start.sh` now defaults `FUSION_IDENTITY_REDIS_URL` (`redis://127.0.0.1:6379/0`) + `FUSION_IDENTITY_GRPC_PORT` (`50051`, the registered fusion-identity-grpc port) and persists both in the env file; previously prod ran with redis unset, so gRPC authorize, concurrency leases and daily-quota counters were all disabled and tenant `fmu_` keys were dead letters. Opt out per deploy by exporting `FUSION_IDENTITY_REDIS_URL` set-but-empty (or `FUSION_IDENTITY_GRPC_PORT=0`)
- #71: `IdentityClient` SDK fixes found by the live enforcement-chain acceptance tests — attach the `x-fusion-service-token` metadata on every rpc (the server interceptor gates all rpcs; the SDK previously sent none and could never authorize), and tolerate the generated health stub's capitalized `Check`
- Acceptance (integration, real PG + redis + real gRPC socket): tenant key authorizes and acquires a lease; `ReportUsage` moves the daily-quota counter; `concurrent=1` makes the second parallel authorize fail `CONCURRENCY_LIMIT_EXCEEDED` (HTTP 429); release restores acquire. Gateway-side identity client config remains upstream (fusion-gateway)

## 0.2.28

- #69: `/refresh` now rate-limited (per-IP + per-account, `FUSION_IDENTITY_REFRESH_RATE_LIMIT` default 60/window) — a client refresh-retry loop issuing token pairs every second could queue logins ~2min behind the churn; garbage refresh tokens now 401 instead of an unhandled 500
- #68: process-wide KDF concurrency cap (`FUSION_IDENTITY_KDF_CONCURRENCY` default 4) — bounds the ~64MB/CPU footprint of unbounded parallel argon2 off-loads under a login burst; slow logins/refreshes (>2s) log a WARNING for diagnosis
- Root cause (both): machine-level CPU starvation (load avg ~146) + fusion-gateway refresh retry loop without backoff (filed upstream); JWKS/issue_token verified IO-free and lock-free

## 0.2.27

Current version (`pyproject.toml`).

- #66: privileged creation paths (register-tenant, provision) seed the admin `email_verified=True` — a second login right after signup succeeds with verification enforced, no SMTP lockout
- #63: auto-created open-join tenants are never admin-less — the founding signup becomes `tenant_admin` (later joiners stay `member`); new service-token endpoint `POST /api/v1/admin/tenants/{id}/admins` promotes an existing member to cure admin-less tenants
- #64: event-loop stall observability — loop-independent watchdog thread (`FUSION_IDENTITY_STALL_WATCHDOG`, default 30s) probes `/health` and logs CRITICAL on stall / INFO-style recovery; all argon2 KDF calls (login, change/reset password, user creation) offloaded to worker threads; `start.sh` persists required env to `~/.fusion-identity/env` (0600) so clean-shell restart works
- #65: registration abuse throttle evidence (per-IP + per-account, 429 + deny logs), logout→401 and single-use refresh rotation tests, stall drill playbook + degradation contract in `docs/ops-runbook.md`
- fix(test): password-reset integration test updated for the PR #61 link contract (`/auth/?reset={token}`)

## 0.2.25

Current version (`pyproject.toml`).

- docs-system v1.1 contract adoption (PR #56): doc frontmatter (doc_id/class/entry/doc_type), `docs/` pages (api-reference, architecture, config-reference, get-started, ops-runbook, product-page, troubleshooting), `ci/validate_docs.py` budget/contract validator, `docs.yml` CI workflow, `AGENTS.md`, `CHANGELOG.md`. Docs-only — no API or schema change.

## 0.2.24

Recent merged work (PR history):

- #53/#54: duplicate-email registration returns 409 (case-insensitive); self-service password recovery (`POST /api/v1/auth/password/forgot`, `/password/reset`) with no-enumeration posture and refresh-family revocation (PR #55)
- #51: absolute verification link matching the auth-portal contract (`{PUBLIC_BASE_URL}/auth/?verify={token}`) (PR #52)
- #48: one-time SSO tickets (`POST /api/v1/auth/ticket`, `/ticket/exchange`) for fusion-site → web-shell handoff (PR #50)

Older releases: see GitHub releases page. Entries are added per release; this file does not restate full PR history.
