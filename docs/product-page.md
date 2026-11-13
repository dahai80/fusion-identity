---
doc_id: fusion-identity/product-page
product: fusion-identity
class: core
entry: service
doc_type: product-page
title: { zh: "fusion-identity 产品页", en: "fusion-identity product page" }
audience: engineer
status: draft
version: 0.2.32
updated: 2026-11-13
owner: "@dahai"
source_of_truth:
  - README.md
  - fusion_identity/store.py
  - fusion_identity/deps.py
---

# fusion-identity 产品页 / Product page

**一句话 / One-liner**: Fusion 多租户体系的租户/身份/授权骨干——唯一 JWT 签发方 + 租户注册中心 + RBAC/配额/审计平面。

The tenant/identity/auth backbone of Fusion: sole JWT issuer, tenant registry, and the RBAC/quota/audit plane every downstream service consumes instead of re-implementing.

## 解决什么问题 / What problem it solves

没有 identity 时,每个 fusion-* 服务都要各自回答:token 怎么签、租户怎么隔离、角色怎么校验、配额怎么扣、审计怎么留痕。fusion-identity 把这五件事收拢为一个服务,下游只消费三样东西:login 拿 token、verify 验 token、gRPC `AuthorizeAndAcquire` 做高并发授权。消费者不再需要自己写:

- JWT 签发/校验/JWKS 轮换(`fusion_identity/jwks.py`、`jwt_utils.py`)
- 跨租户防护(token `tid` vs `X-Tenant-Id` vs 路径 `{tenant_id}` 三方一致,`require_tenant_admin_of`,见 `fusion_identity/deps.py`)
- 租户配额(RPM/TPM/并发/模型白名单,热更新不重启)
- API key 与应用机密的哈希存储、轮换宽限期(`fusion_identity/routes/app_secrets.py`)
- 防篡改审计(hash-chained `audit_log`,支持 OTLP 导出与业务事件回填)

**约束 / Constraints**: 下游必须持有 `FUSION_IDENTITY_SERVICE_TOKEN` 才能调用 verify/admin/SCIM 平面;session token 只能在 `/session/verify` 校验,`/verify`/`/introspect` 按类型不匹配拒绝。租户的创建/删除是 operator-only,无公开 POST/DELETE 端点。

## 核心能力 / Capabilities

| 能力 | 消费者不再写什么 | 限制 |
|---|---|---|
| JWT 签发(HS256/RS256 + JWKS + 24h 宽限 kid 轮换) | 签名/密钥管理代码 | RS256 模式才发布 JWKS;HS256 下 JWKS 返回空 `{keys:[]}` |
| 租户注册 + 成员 + RBAC(4 内置角色 + 每租户自定义角色 ≤64) | 角色矩阵/菜单权限逻辑 | 内置角色不可变;请求方≠审批方为一等校验端点 |
| 配额热更新(rpm/tpm/concurrent/storage_mb/allowed_models) | 配额存储与限流计数 | `tpm` 字段实为每日 token 上限(遗留字段名);Redis 未配置时 RPM fail-open |
| gRPC `IdentityService`(授权+并发租约,Redis Lua 原子) | 高并发授权与租约管理 | 需 `FUSION_IDENTITY_GRPC_PORT>0` 且配置 Redis;否则整平面关闭 |
| API key / app secrets / SaaS credentials 三类机密平面 | `.env` 密钥 stuffing | 原文只返回一次(secrets)或 KEK 加密存取(credentials);平台级 service token 不做按 app 隔离 |
| SCIM 2.0 + OIDC SSO + 邀请/审批/开放三种加入策略 | 入站开通与 SSO 对接代码 | OIDC 回调依赖租户管理员预注册 IdP;`client_secret` 由 KEK 加密 |
| 生命周期事件 outbox(pull 轮询或 HMAC webhook push) | 自建事件广播 | webhook 必须同时配 `WEBHOOK_SECRET`(fail-closed);超过 `MAX_ATTEMPTS`=5 次进入 dead 状态 |

## 三条红线 / Three red lines (multi-tenant PRD)

1. **Fail-closed** — 缺 `tenant_id`、token 无效、缺必需环境变量 → 401 / 拒绝启动,不降级到默认租户。
2. **跨租户拒绝** — 租户 A 的 admin 访问租户 B 的成员/密钥/配额/审计一律 403。
3. **数据隔离分层** — strong = Postgres RLS(migration `0007`,12 张租户表),medium = `tenant_id` 列 + 应用层守卫,namespace = key 前缀;层间不混用。注意:RLS 目前是兜底层(每请求 GUC 激活为待办),`require_tenant_admin_of` 仍是主防线,服务在生产必须以低权限角色 `fusion_identity_app` 连接。

## 边界 / Out of scope

- 不提供用户界面(登录门户路由由 fusion-gateway 的 web/auth 持有)
- 不做 Postgres/Redis 自身的高可用(基础设施前提,见 ops-runbook)
- 不发邮件基础设施,仅对接外部 SMTP relay;未配置时验证 token 走 WARNING 日志(dev fallback)

## 相关页面 / Related pages

- 快速上手: [get-started.md](get-started.md) · API: [api-reference.md](api-reference.md) · 配置: [config-reference.md](config-reference.md) · 架构: [architecture.md](architecture.md) · 故障排查: [troubleshooting.md](troubleshooting.md) · 运维: [ops-runbook.md](ops-runbook.md)
