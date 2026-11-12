---
doc_id: fusion-identity/troubleshooting
product: fusion-identity
class: core
entry: service
doc_type: troubleshooting
title: { zh: "fusion-identity 故障排查", en: "fusion-identity troubleshooting" }
audience: engineer
status: draft
version: 0.2.32
updated: 2026-11-13
owner: "@dahai"
source_of_truth:
  - README.md
  - start.sh
  - docs/ops-runbook.md
  - fusion_identity/config.py
---

# fusion-identity 故障排查 / Troubleshooting

按症状定位。生产运维程序(备份/告警/SLO/轮换)见 [ops-runbook.md](ops-runbook.md)。

## 启动失败 / Fails to start

| 症状 | 原因 | 处置 |
|---|---|---|
| `ERROR: FUSION_IDENTITY_JWT_KEY unset` (start.sh 退出码 2) | fail-closed:签名密钥未设置 | `export FUSION_IDENTITY_JWT_KEY="$(openssl rand -hex 32)"` 后重试 |
| `ERROR: FUSION_IDENTITY_SERVICE_TOKEN unset` | `/verify` 端点会失去保护,拒绝启动 | 设置 >= 24 字节 token |
| `ERROR: FUSION_IDENTITY_KEK unset` / `equals FUSION_IDENTITY_JWT_KEY` | KEK 缺失或与 JWT 密钥同值(密钥隔离要求) | 生成独立 32 字节 KEK |
| 启动即退出,日志见 bootstrap 报错 | 租户表为空且未设置 `FUSION_BOOTSTRAP_ADMIN_USER`/`PASS`(全新安装必须播种第一个 admin) | 设置引导变量(密码 >= 12 字符),或用 `psql` 预先播种;表非空时这些变量可省略 |
| `ERROR: port ... not registered in port-registry.yaml` | register-then-start 自检:端口未登记或与登记不符 | 在 `~/fusion/architecture/port-registry.yaml` 登记;独立部署(无注册表)用 `FUSION_SKIP_REGISTRY_CHECK=1` 旁路 |
| `docker compose` 启动失败 | compose 需要三个必需 env 已导出 | 先 `export` JWT_KEY/SERVICE_TOKEN/KEK 再 `./start.sh compose up` |

日志: `~/.fusion-identity/identity.log`(`./start.sh log [-f]`);PID: `~/.fusion-identity/identity.pid`。

## 健康检查 / Health

- `GET /health` 返回 200 但 `GET /ready` 返回 503:`/ready` 真实探测 store + Redis。检查 Postgres(`FUSION_IDENTITY_DATABASE_URL`)与 Redis(`FUSION_IDENTITY_REDIS_URL`)连通性;编排器应停止路由流量直至 200。
- `start.sh status` 报 not running 但进程存在:PID 文件过期,`rm ~/.fusion-identity/identity.pid` 后重启。

## 登录问题 / Login issues

| 症状 | 含义 | 处置 |
|---|---|---|
| 401 `invalid credentials` | 用户名/密码错误,或用户不属于任何租户 | 核对凭据;检查用户是否有成员关系 |
| 401 `tenant_mismatch` | 显式 `tenant_id` 与用户实际成员关系不符 | 该错误码与 `invalid credentials` 有意区分;确认目标租户 |
| 409 `tenant_ambiguous` + `tenants:[...]` | 用户属于多个租户且未显式传 `tenant_id` | 客户端展示租户选择器后重发登录请求 |
| 403 `email not verified — check your inbox for the verification link` | `EMAIL_VERIFICATION_REQUIRED=1` 且邮箱未验证 | 走邮件链接或 `POST /api/v1/auth/verify-email`;未配 SMTP 时 token 在服务日志 WARNING 行里(dev fallback) |
| `mfa_required: true`,token 为空 | 用户启用了 TOTP | 带 `mfa_code` 重发同请求 |
| 429 / 登录被拒 | IP 限流(默认 10 次/60s) | 调 `FUSION_IDENTITY_LOGIN_RATE_LIMIT` / `_WINDOW`;`0` 不限 |

## Token 校验问题 / Token verification

- 下游 `/verify` 返回 401:确认用的是 **service token**(`Authorization: Bearer $FUSION_IDENTITY_SERVICE_TOKEN`)而非业务 JWT;确认 token 未过期(默认 8h)/未吊销。
- session token 在 `/verify`/`/introspect` 被拒:类型不匹配,属预期行为;session token 只在 `/session/verify` 校验。
- refresh 被拒且整个 family 失效:refresh token 复用检测触发(轮换后复用旧 token 吊销全族),属安全特性。
- RS256 下游验签失败:拉取 `/.well-known/jwks.json`;刚轮换 `kid` 时旧 key 有 24h 宽限,确认下游缓存已刷新。
- 轮换 service token 后下游全部 401:设置 `FUSION_IDENTITY_SERVICE_TOKEN_PREV=<旧>` 双窗口过渡,把调用方迁完再删除 PREV。

## 权限 / 403

- tenant_admin 访问其他租户资源 403:红线 #2,预期行为。检查 `X-Tenant-Id` 与路径 `{tenant_id}` 是否一致且等于 token `tid`。
- 自定义角色 403:deny-by-default;custom role 的 write class 决定授权(`{resource}:write` 隐含读/删);角色菜单矩阵改动在下次 verify 生效。
- 成员管理操作 409/403:last-tenant_admin 与自移除守卫,预期。
- 注册端点 403:`FUSION_IDENTITY_REGISTRATION_ENABLED=0` 时两个注册端点均 403。

## gRPC / 并发租约 / gRPC plane

- `AuthorizeAndAcquire` 不可用:gRPC 仅在 `FUSION_IDENTITY_GRPC_PORT>0` **且**配置 `FUSION_IDENTITY_REDIS_URL` 时启用;两者缺一即整平面关闭。
- `CONCURRENCY_LIMIT_EXCEEDED`:确认调用了 `ReleaseLease`/`ReportUsage` 释放;租约 TTL 默认 120s 自动过期。
- `DAILY_QUOTA_EXCEEDED`:注意 `tpm` 配额字段实为**每日** token 上限(遗留字段名);经 admin quotas API 调整。
- `RATE_LIMIT_EXCEEDED`:RPM 60s 滑窗;`quotas.rpm=0` 关闭;Redis 未配置时 fail-open。

## 机密与 KEK / Secrets and KEK

- `GET /api/v1/apps/{app_id}/credentials/{name}` 返回 500:KEK 不匹配(密文解不开),这是运维事故不是 404——检查 KEK 是否被轮换/换错;轮换期间应配置 `FUSION_IDENTITY_KEK_PREV`。
- app secret 过期:grace 窗口(默认 24h)关闭后版本读作 `expired`;重新 rotate 并让消费端 decrypt-and-re-encrypt。
- webhook 事件 `dead` 状态:投递超过 `FUSION_IDENTITY_WEBHOOK_MAX_ATTEMPTS`(默认 5)次;事件仍在 outbox 可查询,修复端点后从 outbox 重放;确认 `WEBHOOK_SECRET` 已设置(URL 无 secret 会拒启)。

## 数据库 / RLS

- RLS 未生效:确认服务以低权限角色 `fusion_identity_app` 连接(superuser/BYPASSRLS 绕过 RLS);migration `0007` 创建的角色默认密码必须轮换。
- 迁移失败/孤儿记录:`migration_orphans` 表记录;`PgStore` 启动时幂等重放 `migrations/`,检查该表定位。
- 集成测试失败:需真实 Postgres(`deploy/sql/schema.sql`)+ Redis;RLS 用例还要 `FUSION_IDENTITY_APP_ROLE_URL` 指向轮换过密码的低权限角色。

## 指标与观测 / Metrics

- `GET /metrics` 无鉴权,可接 Prometheus;关键序列:`fusion_identity_auth_requests_total{tenant_id,target_module,status_code,result}`、`fusion_identity_rpc_latency_seconds{method}`、`fusion_identity_tenant_active_concurrency{tenant_id}`、`fusion_identity_quota_remaining{tenant_id}`。
- 结构化排查:设置 `FUSION_IDENTITY_LOG_JSON=1`,每行日志带 `tenant_id`/`user_id`。

## 仍无法解决 / Escalation

按 [ops-runbook.md](ops-runbook.md) 的 on-call 升级路径处理;开 issue 前附上 `/health`、`/ready` 输出与最近 100 行日志(`./start.sh log 100`)。
