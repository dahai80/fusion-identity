---
doc_id: fusion-identity/config-reference
product: fusion-identity
class: core
entry: service
doc_type: config-reference
title: { zh: "fusion-identity 配置参考", en: "fusion-identity config reference" }
audience: engineer
status: draft
version: 0.2.31
updated: 2026-11-11
owner: "@dahai"
source_of_truth:
  - README.md
  - fusion_identity/config.py
  - start.sh
---

# fusion-identity 配置参考 / Config reference

全部配置经环境变量注入(无配置文件);解析在 `fusion_identity/config.py`,端口经 `fusion_core.config.service_port` 单点解析。fail-closed 变量缺失时服务拒绝启动。

## 必需变量 / Required

| 变量 | 默认 | 说明 / Notes |
|---|---|---|
| `FUSION_IDENTITY_JWT_KEY` | — | HS256 签名密钥,>= 32 字节;缺失拒启 |
| `FUSION_IDENTITY_SERVICE_TOKEN` | — | 共享服务 token,>= 24 字节;守卫 `/verify`、admin、SCIM、usage 平面;缺失拒启 |
| `FUSION_IDENTITY_KEK` | — | IdP `client_secret` + TOTP secret 的 AES-256-GCM 加密密钥(HKDF-SHA256 派生);必须显式设置且不得等于 `JWT_KEY`;缺失或同值拒启 |

## JWT / 签名

| 变量 | 默认 | 说明 / Notes |
|---|---|---|
| `FUSION_IDENTITY_JWT_ALGORITHM` | `HS256` | `HS256` 或 `RS256` |
| `FUSION_IDENTITY_JWT_PRIVATE_KEY_PEM` | — | RS256 私钥 PEM;未设置则启动时生成 |
| `FUSION_IDENTITY_JWT_ISSUER` | `fusion-identity` | `iss` claim |
| `FUSION_IDENTITY_JWT_AUDIENCE` | `fusion-cluster` | `aud` claim |
| `FUSION_IDENTITY_JWT_TTL` | `28800` | access token TTL(秒,8h) |
| `FUSION_IDENTITY_REFRESH_TTL` | `604800` | refresh token TTL(秒,7d) |

## 服务 / 网络

| 变量 | 默认 | 说明 / Notes |
|---|---|---|
| `FUSION_IDENTITY_HOST` | `127.0.0.1` | 绑定地址;绑 `0.0.0.0` 需在 port-registry `purpose` 字段记录理由 |
| `FUSION_IDENTITY_PORT` | `11470` | 监听端口 |
| `FUSION_REGISTRY` | `~/fusion/architecture/port-registry.yaml` | register-then-start 自检的注册表路径;文件缺失仅告警 |
| `FUSION_SKIP_REGISTRY_CHECK` | `0` | `1` 旁路注册表自检 |

## 存储 / 依赖

| 变量 | 默认 | 说明 / Notes |
|---|---|---|
| `FUSION_IDENTITY_DATABASE_URL` | `postgresql://127.0.0.1:5432/fusion_identity` | Postgres 连接串;生产必须以低权限角色 `fusion_identity_app` 连接,RLS 才生效 |
| `FUSION_IDENTITY_USE_PGSTORE` | 未设置 | 未设置时 `build_app()` 用 `InMemoryStore`(测试/bootstrap);生产必须设置并注入 `PgStore` |
| `FUSION_IDENTITY_DB_POOL_MAX` | `8` | `PgStore` 连接池上限;生产建议 20-50 |
| `FUSION_IDENTITY_REDIS_URL` | `redis://127.0.0.1:6379/0`(经 start.sh 默认开启, issue #71) | 热缓存 + 并发租约 + gRPC 平面依赖;进程内未设置仍为 REST-only。按部署退出:导出 set-but-empty |
| `FUSION_IDENTITY_GRPC_PORT` | `50051`(经 start.sh 默认开启, issue #71) | 仅在 `>0` 且配置 Redis 时启用 gRPC;导出 `0` 显式禁用 |
| `FUSION_IDENTITY_LEASE_TTL` | `120` | 并发租约 TTL(秒) |

## 引导 / Bootstrap

| 变量 | 默认 | 说明 / Notes |
|---|---|---|
| `FUSION_BOOTSTRAP_ADMIN_USER` | — | 引导 `tenant_admin` 用户名 |
| `FUSION_BOOTSTRAP_ADMIN_PASS` | — | 引导密码;设置时必须 >= 12 字符(fail-closed)。租户表为空的全新安装必须提供,否则拒启;表非空则跳过 bootstrap |
| `FUSION_BOOTSTRAP_TENANTS` | — | JSON 数组,额外播种租户,如 `[{"tenant_id":"acme","display_name":"Acme","plan":"team"}]` |

## 密钥轮换双窗口

| 变量 | 默认 | 说明 / Notes |
|---|---|---|
| `FUSION_IDENTITY_KEK_PREV` | — | KEK 轮换期间的旧密钥;必须不同于 `KEK`/`JWT_KEY`;清扫后删除 |
| `FUSION_IDENTITY_SERVICE_TOKEN_PREV` | — | 服务 token 轮换期间新旧双收(恒时比较);必须 >= 24 字节且不同于当前值 |
| `FUSION_IDENTITY_SECRET_GRACE_SECONDS` | `86400` | 应用机密轮换默认宽限窗口(24h) |

## 日志 / 限流 / MFA

| 变量 | 默认 | 说明 / Notes |
|---|---|---|
| `FUSION_IDENTITY_LOG_LEVEL` | `INFO` | 日志级别 |
| `FUSION_IDENTITY_LOG_JSON` | `0` | `1` = 结构化 JSON 日志,带 `tenant_id`/`user_id` |
| `FUSION_IDENTITY_LOGIN_RATE_LIMIT` | `10` | 每 IP 每窗口最大登录数;`0` = 不限 |
| `FUSION_IDENTITY_LOGIN_RATE_WINDOW` | `60` | 限流窗口(秒);同时作用于 `/register` + `/register-tenant`(按 IP 和按账号) |
| `FUSION_IDENTITY_REFRESH_RATE_LIMIT` | `60` | `/refresh` 每 IP+账号限流预算(issue #69,防刷新重试风暴);`0` 关闭 |
| `FUSION_IDENTITY_KDF_CONCURRENCY` | `4` | 离循环 argon2 并发上限(issue #68,防登录突发把机器打满);超出的排队 |
| `FUSION_IDENTITY_STALL_WATCHDOG` | `30` | 停摆看门狗探测 `/health` 的间隔(秒),停摆打 CRITICAL、恢复打 WARNING;`0` 关闭(issue #64) |
| `FUSION_IDENTITY_MFA_ENFORCE_ADMIN` | `0` | `1` = `tenant_admin` 登录在启用 TOTP 前拒绝(AAL2) |

## 注册 / 邮箱 / SSO

| 变量 | 默认 | 说明 / Notes |
|---|---|---|
| `FUSION_IDENTITY_REGISTRATION_ENABLED` | `1` | `0` → 两个注册端点返回 403 |
| `FUSION_IDENTITY_EMAIL_VERIFICATION_REQUIRED` | `1` | `1` = 注册需邮箱 + 单用验证 token,验证前登录 403 |
| `FUSION_IDENTITY_EMAIL_VERIFY_TTL` | `86400` | 验证 token TTL(秒) |
| `FUSION_IDENTITY_REGISTRATION_DEFAULT_TENANT` | `community` | 个人注册自动加入的租户(缺失时自动创建 free 模板) |
| `FUSION_IDENTITY_SSO_TICKET_TTL` | `60` | SSO ticket 生命周期(秒,钳制 5–600) |
| `FUSION_IDENTITY_PASSWORD_RESET_TTL` | `3600` | 密码重置 token TTL(秒)——bearer 能力,保持短 |
| `FUSION_IDENTITY_PUBLIC_BASE_URL` | — | 验证/重置链接的公开 origin(`{base}/auth/?verify={token}`,契约归 fusion-gateway);未设置则相对链接 + WARNING |
| `FUSION_IDENTITY_SMTP_HOST` | —(日志回退) | SMTP relay;未设置时验证 token 走 WARNING 日志(dev fallback),验证仍拦登录 |
| `FUSION_IDENTITY_SMTP_PORT` | `587` | SMTP 端口 |
| `FUSION_IDENTITY_SMTP_USERNAME` / `_PASSWORD` | — | SMTP AUTH 凭证 |
| `FUSION_IDENTITY_SMTP_FROM` | — | 发件地址 |
| `FUSION_IDENTITY_SMTP_STARTTLS` | `1` | 连接 relay 时使用 STARTTLS |
| `FUSION_IDENTITY_PAYMENT_PROVIDER` | `stub` | issue #74:充值平面支付渠道;`stub` 即时确认(仅开发/测试),未知值 fail-closed(503) |
| `FUSION_IDENTITY_FIRST_PURCHASE_PROMO_PCT` | `20` | issue #74:租户首笔已支付订单的赠送代币百分比,`0` 关闭 |
| `FUSION_IDENTITY_SERVICE_ACCOUNT_TTL` | `900` | issue #76:服务账号会话 token TTL(秒,钳制 ≥60);无 refresh,机器重新换凭 |

## 事件 / Webhook

| 变量 | 默认 | 说明 / Notes |
|---|---|---|
| `FUSION_IDENTITY_WEBHOOK_URL` | —(禁用) | outbox 推送端点;必须同时设置 `WEBHOOK_SECRET`,否则拒启(fail-closed);未设置 = pull-only |
| `FUSION_IDENTITY_WEBHOOK_SECRET` | — | HMAC-SHA256 签名密钥(`X-Fusion-Signature: sha256=<hex>`) |
| `FUSION_IDENTITY_WEBHOOK_TICK` | `5` | webhook worker 轮询间隔(秒) |
| `FUSION_IDENTITY_WEBHOOK_MAX_ATTEMPTS` | `5` | 投递尝试上限,超过后事件 `dead`(仍可查询) |

## 约束速查 / Constraint quick list

- `KEK` / `KEK_PREV` / `JWT_KEY` 三者两两不同(config 显式校验)。
- 端口必须先在 `port-registry.yaml` 登记(start.sh 自检),`11400-11499` 为 fusion-* 服务段。
- 未设置 `FUSION_IDENTITY_USE_PGSTORE` 时使用内存存储——仅限测试,生产数据不落盘。
