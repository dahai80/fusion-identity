---
doc_id: fusion-identity/changelog
product: fusion-identity
class: core
entry: service
doc_type: changelog
title: { zh: "fusion-identity 变更日志", en: "fusion-identity changelog" }
audience: engineer
status: draft
version: 0.2.31
updated: 2026-11-11
owner: "@dahai"
source_of_truth:
  - pyproject.toml
  - README.md
---

# Changelog

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
