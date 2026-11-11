---
doc_id: fusion-identity/architecture
product: fusion-identity
class: core
entry: service
doc_type: architecture
title: { zh: "fusion-identity 架构", en: "fusion-identity architecture" }
audience: engineer
status: draft
version: 0.2.28
updated: 2026-11-11
owner: "@dahai"
source_of_truth:
  - README.md
  - fusion_identity/app.py
  - fusion_identity/store.py
  - fusion_identity/db.py
  - migrations/
---

# fusion-identity 架构 / Architecture

## 定位 / Position

Fusion 生态 Base Framework 层(与 `fusion-core` 并列)的租户/身份/授权骨干。实现多租户 PRD §3(租户模型)、§4(租户上下文 fabric)与附录 A(schema + JWT claims)。所有 fusion-* 服务消费它,不重复实现。外部流量经 fusion-gateway 到达;服务自身默认只绑 `127.0.0.1:11470`。

```
                 +---------------------+
   browsers ---> | fusion-gateway      |  session tokens (POST /session, /session/verify)
                 +---------------------+
                          |
   downstream services -> | REST :11470   login / verify / introspect / admin / SCIM / apps
   inference gateways --> | gRPC :50051   AuthorizeAndAcquire / ReleaseLease / ReportUsage
                          |
                 +---------------------+        +---------+
                 | fusion-identity     | -----> | Postgres|  fusion_identity (24 tables, RLS)
                 | FastAPI + gRPC      | -----> | Redis   |  cache + concurrency leases (Lua)
                 +---------------------+        +---------+
```

## 模块分层 / Module map

| 模块 | 职责 |
|---|---|
| `fusion_identity/app.py` | FastAPI 组装 + `main()` 入口(pyproject script `fusion-identity`),`build_app()` 按环境选 store |
| `fusion_identity/routes/` | 22 个路由模块(auth、tenants、members、rbac、oidc、scim、admin、app_secrets、app_credentials、mfa、join、registration 等),薄封装,守卫在 deps |
| `fusion_identity/deps.py` | `require_permission[_of]` 权限点依赖工厂、`require_tenant_admin_of` 跨租户守卫(三方一致:token `tid` vs `X-Tenant-Id` vs 路径) |
| `fusion_identity/store.py` | 存储接口 + 内置角色权限矩阵 `BUILTIN_ROLE_MATRIX`(deny-by-default 权威) |
| `fusion_identity/db.py` | `PgStore` 生产实现;启动时跑 `migrations/` 幂等迁移(`ensure_schema`) |
| `fusion_identity/auth.py` | 登录/refresh 轮换 family/MFA/TOTP 校验等核心逻辑 |
| `fusion_identity/crypto.py` / `jwks.py` / `jwt_utils.py` | argon2id、AES-256-GCM(HKDF 派生自 KEK)、JWKS 与 kid 轮换(24h grace)、JWT 签发 |
| `fusion_identity/cache.py` / `ratelimit.py` / `concurrency.py` | Redis 热缓存(TTL <= 300s,写路径主动失效)、登录限流、Lua 原子租约 |
| `fusion_identity/grpc_*` | gRPC `IdentityService` servicer/interceptor/health |
| `fusion_identity/client/` | 网关侧 Python SDK(`IdentityClient`、`lease_guard`) |
| `fusion_identity/events.py` / `email_sender.py` / `metrics_collector.py` | outbox 事件 + webhook worker、SMTP(未配置走 WARNING 日志回退)、Prometheus 指标 |

## 存储与隔离 / Storage and isolation

Postgres 库 `fusion_identity`(单库收敛,issue #26/DB-2),24 张表:migration 目录 `migrations/0001`–`0020` 幂等演进。要点:

- **三层隔离**:strong = RLS(`0007_rls_strong_isolation.sql`,12 张租户表,`app.current_tenant` GUC 门控,`_system` 为平台哨兵);medium = `tenant_id` 列 + 应用层守卫(当前主防线);namespace = key 前缀。生产必须以低权限角色 `fusion_identity_app` 连接,RLS 才能绑定(superuser/BYPASSRLS 绕过)。每请求 GUC 激活是已登记的后续项。
- **凭据**:argon2id 哈希(每用户盐);refresh token 记录轮换 family(复用即全族吊销);audit_log 哈希链 + 原子序列。
- **机密平面**:`app_secrets`(sha256 落库,原文仅一次,轮换 grace 窗口)与 `app_credentials`(KEK 加密,可取回)为平台级表(无 tenant_id、无 RLS,同 `plan_templates` 信任级)。

## 两个平面 / Two planes

- **REST/HTTP(:11470)**:浏览器侧登录(经 gateway)、服务间 verify/introspect、admin/SCIM/开通平面(service token)。
- **gRPC(:50051,可选)**:推理网关的高并发授权。`AuthorizeAndAcquire` 在一次调用内完成 api_key 校验 → 白名单 → RPM(60s 滑窗)→ 日配额 → Redis Lua 原子租约;`ReportUsage` 回填用量。未配置 Redis 或端口 0 时整平面关闭(fail-closed 而非降级模拟)。

## 一致性模型 / Consistency

- 多实例共享一个 Postgres 时应用层一致(租户可见性、jti 吊销、审计链、用量聚合;`tests/test_ha_consistency.py` 验证)。Postgres/Redis 自身 HA 是基础设施前提。
- 配置变更经缓存失效在秒级生效(键 TTL <= 300s);RPM `rpm=0` 关闭限流,Redis 缺失时 fail-open(与日配额同模式)。
- 生命周期变更加事务性 outbox(`event_outbox`),pull(`next_cursor` 轮询)或 push(HMAC webhook,5 次失败后 dead)。

## 消费者契约 / Consumer contract

下游服务只需要:三个环境变量(service token 等)与一次 `POST /api/v1/auth/verify` 或一次 gRPC `AuthorizeAndAcquire`。机密材料按 `app_id` 命名空间从 `/api/v1/apps/...` 取,不塞 `.env`。service token 本身是平台级凭据,泄漏即轮换(支持 `_PREV` 双窗口)。

## 测试与质量 / Tests

- `pytest tests/ -v`:219 离线用例(InMemoryStore + fakeredis)。
- `pytest tests/ -m integration -v`:15 用例(PgStore 生命周期、Redis Lua 真跑、RLS 隔离)。
- RBAC 矩阵与守卫清单由 `tests/test_rbac_matrix.py` 断言(零隐式访问)。
