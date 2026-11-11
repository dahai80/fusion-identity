---
doc_id: fusion-identity/api-reference
product: fusion-identity
class: core
entry: service
doc_type: api-reference
title: { zh: "fusion-identity API 参考", en: "fusion-identity API reference" }
audience: engineer
status: draft
version: 0.2.29
updated: 2026-11-11
owner: "@dahai"
source_of_truth:
  - README.md
  - fusion_identity/routes/
  - fusion_identity/app.py
---

# fusion-identity API 参考 / API reference

Base URL: `http://127.0.0.1:11470`(默认绑定,PRD C8)。错误响应统一为 `{"detail": string}` + HTTP 状态码。

租户作用域路由同时要求 `Authorization: Bearer <jwt>` 与 `X-Tenant-Id: <tid>`,token `tid` 必须与两者一致。每个路由声明显式 `(resource, action)` 权限点(`fusion_identity/deps.py` 的 `require_permission[_of]`),deny-by-default。

## Auth — `/api/v1/auth`

| Method | Path | Auth | 说明 / Notes |
|---|---|---|---|
| POST | `/login` | none | `{username,password,tenant_id?,mfa_code?}` → `{access_token,refresh_token,must_change_password,mfa_required}`。有 TOTP 因子且缺 `mfa_code` → `mfa_required=true` 空 token。`tenant_id` 缺省时由成员关系解析:单一租户自动选定,多租户 409 `tenant_ambiguous`,无成员 `invalid credentials`;显式给了不属于该用户的租户 → 401 `tenant_mismatch`。邮箱未验证 → 403 |
| GET | `/verify?token=` / POST `/verify` | service token | 返回 `{tid,role,scopes,quota,tenant_status,write_classes,allowed_menus}`;session token 在此按类型不匹配拒绝 |
| POST | `/introspect` | service token | RFC 7662;JSON 或 form-encoded;无效/撤销/过期返回 `{active:false}` |
| POST | `/refresh` | none | `{refresh_token}` → 轮换的新对;复用已轮换 token 吊销整个 family |
| POST | `/ticket` | bearer | 一次性 SSO ticket(`fsso_…`,TTL 默认 60s,钳制 5–600),仅存 sha256 |
| POST | `/ticket/exchange` | none | `{ticket}` → 标准 token 对;原子单用,重放 401,登录级限流 |
| POST | `/logout` | bearer | `{refresh_token?}` 吊销 access jti + refresh |
| POST | `/revoke` | bearer (tenant_admin) | `{jti}` 吊销(归属入审计) |
| DELETE | `/sessions` | service token | `{sub,tenant_id}` 吊销该主体全部 access/session jti 与 refresh family(幂等,未知租户 404) |
| POST | `/password` | bearer | `{old_password,new_password}`(NIST 800-63B 策略) |
| POST | `/password/forgot` | none | `{email}` → 恒 `{sent:true}`(防枚举);token `secrets.token_urlsafe(32)`,sha256 落库,TTL 默认 3600s |
| POST | `/password/reset` | none | `{token,new_password}` → 原子单用;成功后轮换 argon2id 哈希并吊销全部 refresh family;无效/过期/重放统一 400 |

## 注册与邮箱验证 — `/api/v1/auth/register*`

| Method | Path | Auth | 说明 / Notes |
|---|---|---|---|
| POST | `/register` | none | 个人注册;自动加入 `FUSION_IDENTITY_REGISTRATION_DEFAULT_TENANT`(默认 `community`,首次自动创建 free 模板),role `member`;验证开启时返回 `{status:"verification_required"}`;用户名/邮箱(大小写不敏感)冲突 409;`REGISTRATION_ENABLED=0` → 403 |
| POST | `/register-tenant` | none | 租户注册;`admin_password` 必须 >= 12;复用 `provision_core`,支持 `Idempotency-Key` 重放;密码不回显 |
| POST | `/verify-email` | none | `{token}` 原子单用;无效/过期/重放统一 400 |
| POST | `/verify-email/resend` | none | `{username}`;响应恒 `{resent:bool}`(防枚举);PUBLIC by design |

## Session tokens — `/api/v1/auth/session`(Union Web R-2)

| Method | Path | Auth | 说明 / Notes |
|---|---|---|---|
| POST | `/session` | service token | `{sub?="web-shell",tenant_id?="local",role?="member",ttl_seconds?(60..86400,默认 43200)}` → `{access_token,jti,expires_in,role}`;`local` 租户幂等自动创建,其他租户必须已存在且 active |
| POST | `/session/verify` | service token | `{token}` → `{valid,sub,tid,tenant,role,scope,iat,exp,jti,type}` 或 401;只认 `type=session` |

## MFA — `/api/v1/auth/mfa`(bearer,仅本人)

| Method | Path | 说明 / Notes |
|---|---|---|
| POST | `/enroll` | 生成 TOTP 密钥(AES-GCM/KEK 加密落库),`secret` + `otpauth_uri` 仅此一次返回 |
| POST | `/verify` | `{code,method}` 确认启用 |
| GET | `` | 列出本人因子(不含密钥) |
| DELETE | `/{method}` | 移除因子 |

`FUSION_IDENTITY_MFA_ENFORCE_ADMIN=1` 时 `tenant_admin` 登录在启用 TOTP 前被拒绝(AAL2)。

## 加入策略 — invites / join-requests

| Method | Path | Auth | 说明 / Notes |
|---|---|---|---|
| POST/GET | `/api/v1/tenants/{tid}/invites` | tenant_admin | 邀请 token `finv_` 前缀,原文只显示一次;`ttl_seconds` 60..2592000 |
| POST | `/api/v1/auth/invites/redeem` | bearer | 单用+过期原子校验 |
| POST | `/api/v1/auth/tenants/{tid}/join` | bearer | 仅 `join_policy=open`;role 强制 `member` |
| POST/GET | `/api/v1/tenants/{tid}/join-requests` | bearer / tenant_admin | `approval` 策略流;approve 授予 `member` |

## 租户与成员 — `/api/v1/tenants[/{tid}/...]`

- 租户:`GET`(仅返回调用者自己的 tid)/ `GET /{tid}` / `PATCH /{tid}`(display_name/status/plan)。创建/删除为 operator-only,无公开端点。
- `.../members`:`POST`(add-or-create,新用户 `must_change_password=true`)、`GET`、`PATCH .../{user_id}`(角色)、`PATCH .../{user_id}/status`、`POST .../{user_id}/password`、`DELETE`;有 last-tenant_admin 与自移除守卫。
- `.../api-keys`:`POST`/`GET`/`DELETE`,SHA-256 哈希落库。
- `.../quotas`:`GET`/`PUT`(热更新,含 `default_priority`/`allowed_modules`)。
- `.../audit`:`GET`(`limit` 1..1000,`since`/`until`/`cursor`,self-query only)+ `GET .../audit/verify`(链完整性校验)。
- `.../usage`:`POST`(service token 上报)、`GET`(admin 聚合)、`GET /usage/summary`;`GET /config`、`GET /export`(`?format=csv` 可选)。
- `.../departments`:CRUD,`tool_allowlist` 每部门工具白名单。
- `.../audit/events`(POST,service token)、`.../audit/business-events`(POST/GET,业务事件入链,GIN 索引)、`.../audit/otlp`(GET,OTLP/JSON 导出)。
- `.../idps`:OIDC IdP CRUD,`client_secret` KEK 加密、永不回显。
- `.../roles` / `.../menus` / `.../approvals/validate`:自定义角色(≤64/租户)、role↔menu 矩阵(改后下次 verify 生效)、请求方≠审批方校验。

## Admin 平面 — `/api/v1/admin`(service token,`X-Tenant-Id: _system`)

| Method | Path | 说明 / Notes |
|---|---|---|
| GET/POST | `/tenants` | 列出 / 创建租户(409 冲突;配额字段播种 quotas) |
| PUT | `/tenants/{tid}` | 更新租户/配额 |
| GET | `/tenants/{tid}/quota` | 读配额行 |
| POST | `/tenants/{tid}/api-keys` 或 `/keys` | 铸造 API key,原文仅返回一次 |
| DELETE | `/tenants/{tid}/api-keys/{key_id}` 或 `/keys/{key_id}` | 吊销 |
| GET | `/tenants/{tid}/usage/today` | 24h 并发 + token 用量 |
| GET | `/tenants/{tid}/members/summary` | `{total,active,disabled,locked,by_role}`,不含用户名/邮箱 |
| POST | `/tenants/{tid}/admins` | 提升已有成员为 `tenant_admin`(治理无管理员租户,issue #63);已是 admin 返回 `changed:false` |
| GET | `/tenants/{tid}/idps/summary` | SSO 能力状态,不含 secret 材料 |
| GET | `/app-secrets` | 跨 app 机密清单(无密钥材料) |
| POST | `/tenants/provision` | 一次性开通:租户+配额模板+种子 admin+API key;`Idempotency-Key` 重放返回原结果 |
| GET/PUT | `/plan-templates[/{plan}]` | free/starter/standard/pro/enterprise 内置,可 upsert |
| GET | `/events?cursor=&limit=` | outbox 增量拉取,返回 `next_cursor` |
| POST | `/kek/reencrypt` | KEK 轮换后的重加密清扫 |

## 应用机密与凭证 — `/api/v1/apps/{app_id}/...`(service token,`_system`)

| Method | Path | 说明 / Notes |
|---|---|---|
| POST | `/{app_id}/secrets` | 签发 `fms_` 机密,原文仅一次;已有 current 版本 409(用 rotate) |
| GET | `/{app_id}/secrets` | 版本清单(无材料),状态 `current`/`grace`/`expired`/`revoked` |
| POST | `/{app_id}/secrets/rotate` | 轮换;旧版本进入 grace 窗口(默认 86400s) |
| DELETE | `/{app_id}/secrets/{version}` | 立即吊销(泄露应急) |
| PUT | `/{app_id}/credentials/{name}` | 存/覆盖第三方 SaaS 凭证(KEK 加密,upsert 即轮换) |
| GET | `/{app_id}/credentials/{name}` | 取回原文(404 未存;KEK 不匹配 500,视为运维事故) |

`app_id` 匹配 `^[a-z0-9][a-z0-9_-]{0,63}$`。

## 其他平面

- **JWKS**:`GET /.well-known/jwks.json`(公开);`POST /.well-known/jwks/rotate`(service token,RS256 only,旧 kid 保留 24h)。
- **OIDC SSO**:`GET /api/v1/auth/oidc/{idp_id}/login`(302 → IdP);`POST .../callback`(`{code,state}` → 自动开通 + Fusion JWT)。
- **SCIM 2.0**:`/scim/v2/Users`、`/scim/v2/Groups`,service token + `?tenantId=`;PATCH 走 RFC 7644 `Operations`。
- **Metrics**:`GET /metrics`,无鉴权,Prometheus 文本格式(含 `fusion_identity_auth_requests_total`、`fusion_identity_rpc_latency_seconds`、`fusion_identity_tenant_active_concurrency` 等)。
- **Health**:`GET /health`(静态存活)、`GET /ready`(探测 store+Redis,失败 503)。

## gRPC `fusion.identity.v1.IdentityService`

启用条件:`FUSION_IDENTITY_GRPC_PORT>0` 且已配置 `FUSION_IDENTITY_REDIS_URL`。Proto: `fusion_identity/grpc/identity.proto`(改动后跑 `scripts/gen_proto.sh`)。

| RPC | 说明 / Notes |
|---|---|
| `AuthorizeAndAcquire` | api_key → 租户上下文 + 模块/模型白名单 + RPM + 日配额 + 并发租约(Redis Lua 原子);请求可带 `tenant_id` 交叉校验(不匹配 fail-closed);拒绝码:`INVALID_API_KEY` / `TENANT_DISABLED` / `MODULE_UNAUTHORIZED` / `MODEL_UNAUTHORIZED` / `CONCURRENCY_LIMIT_EXCEEDED` / `DAILY_QUOTA_EXCEEDED` / `RATE_LIMIT_EXCEEDED` |
| `ReleaseLease` | 释放租约 |
| `ReportUsage` | 记 token 用量(日配额计数)+ 释放租约 + 追加 usage ledger |

客户端 SDK 在 `fusion_identity/client/`(`IdentityClient`、`lease_guard` 异步上下文管理器,`KV_PREFIX = "fusion:identity:"`)。
