---
doc_id: fusion-identity/changelog
product: fusion-identity
class: core
entry: service
doc_type: changelog
title: { zh: "fusion-identity 变更日志", en: "fusion-identity changelog" }
audience: engineer
status: draft
version: 0.2.26
updated: 2026-11-11
owner: "@dahai"
source_of_truth:
  - pyproject.toml
  - README.md
---

# Changelog

All notable changes are tracked via GitHub releases and merged PRs. Version in `pyproject.toml` is the source of truth for the current release.

## 0.2.26

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
