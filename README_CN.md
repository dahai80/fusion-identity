# fusion-identity

Fusion 生态的租户身份服务 —— 全生态**唯一 JWT 签发方**与**租户注册表**，为所有 Fusion 服务提供多租隔离能力。

实现多租户 PRD §3（租户模型）、§4（租户上下文织物）与附录 A（schema + JWT claims）。位于**基础框架层**，与 `fusion-core` 并列；ecosystem 层服务只消费、不重新实现。

## 职责

- **JWT 签发** —— `HS256` access + refresh token。Claims：`sub`、`tid`、`tenant`、`role`、`scope`、`iat`、`exp`、`iss`、`aud`、`jti`。签发方 `fusion-identity`，受众 `fusion-cluster`。
- **租户注册表** —— 租户 CRUD（`tenant_id`、`display_name`、`plan`、`status`）。
- **成员 + RBAC** —— 4 个统一角色：`tenant_admin` / `operator` / `member` / `viewer`。每次受保护调用都从 `tenant_members` 重新校验角色（token 中的 role 仅为参考，非不可变）。
- **配额** —— 每租户 `rpm` / `tpm` / `concurrent` / `storage_mb` / `allowed_models` / `allowed_modules` / `default_priority`，热更新（无需重启）。
- **API 密钥** —— 每租户 scoped key，存储用 SHA-256 哈希。
- **审计日志** —— 仅追加、哈希链、仅可自查（租户 A 的 admin 不能读租户 B 的审计）。
- **Token 校验端点** —— 服务间 `POST /api/v1/auth/verify`，由共享的**服务令牌**（`FUSION_IDENTITY_SERVICE_TOKEN`）门控。下游服务调用它校验 bearer token。

## 三条红线（多租户 PRD）

1. **Fail-closed** —— 缺 `tenant_id`、token 无效、或缺必填环境变量（`FUSION_IDENTITY_JWT_KEY`、`FUSION_IDENTITY_SERVICE_TOKEN`）→ `401` 或拒绝启动。无默认租户降级。
2. **跨租户拒绝** —— 租户 A 的 `tenant_admin` 访问租户 B 的 members/api-keys/quotas/audit 会被 403 拦截。由 `require_tenant_admin_of()` 校验：token `tid` 必须同时匹配 `X-Tenant-Id` 头与路径中的 `{tenant_id}`。
3. **数据隔离分层** —— 强 = Postgres RLS（生产），中 = `tenant_id` 列 + 守卫（本服务），命名空间 = key 前缀。层之间不混用。

## 快速开始

```bash
cd /Users/dahai/fusion
source .venv/bin/activate
pip install -e fusion-identity

# fail-closed：两个环境变量都是必填
export FUSION_IDENTITY_JWT_KEY="$(openssl rand -hex 32)"
export FUSION_IDENTITY_SERVICE_TOKEN="$(openssl rand -hex 24)"
export FUSION_BOOTSTRAP_ADMIN_USER=admin
export FUSION_BOOTSTRAP_ADMIN_PASS=adminpass

./fusion-identity/start.sh start
curl -s http://127.0.0.1:11470/health   # {"status":"ok","service":"fusion-identity",...}
```

默认**只绑 127.0.0.1**（PRD C8 —— 不对外暴露，流量经网关进入）。

## 环境变量

| 变量 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `FUSION_IDENTITY_JWT_KEY` | **是** | — | HS256 签名密钥。缺则拒绝启动。 |
| `FUSION_IDENTITY_SERVICE_TOKEN` | **是** | — | 门控 `/verify` 的共享令牌。 |
| `FUSION_IDENTITY_HOST` | 否 | `127.0.0.1` | 绑定地址。 |
| `FUSION_IDENTITY_PORT` | 否 | `11470` | 监听端口。 |
| `FUSION_IDENTITY_DATABASE_URL` | 否 | `postgresql://127.0.0.1:5432/fusion_tenant` | Postgres 连接串。 |
| `FUSION_IDENTITY_JWT_ISSUER` | 否 | `fusion-identity` | JWT `iss`。 |
| `FUSION_IDENTITY_JWT_AUDIENCE` | 否 | `fusion-cluster` | JWT `aud`。 |
| `FUSION_IDENTITY_JWT_TTL` | 否 | `28800`（8h） | access token TTL，秒。 |
| `FUSION_IDENTITY_REFRESH_TTL` | 否 | `604800`（7d） | refresh token TTL，秒。 |
| `FUSION_BOOTSTRAP_ADMIN_USER` | 否 | — | 引导 `tenant_admin` 用户名。 |
| `FUSION_BOOTSTRAP_ADMIN_PASS` | 否 | — | 引导 `tenant_admin` 密码。 |
| `FUSION_IDENTITY_LOG_LEVEL` | 否 | `INFO` | 日志级别。 |

未设 `FUSION_BOOTSTRAP_ADMIN_USER`/`PASS` 且租户表为空时跳过引导 —— 操作员需自行建第一个 admin（fail-closed）。

## API

所有租户级路由需 `Authorization: Bearer <jwt>` 与 `X-Tenant-Id: <tid>` 头，token 的 `tid` 必须与二者都匹配。

### Auth（`/api/v1/auth`）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/login` | 无 | `{username,password,tenant_id}` → `{access_token,refresh_token,...}` |
| GET | `/verify?token=` | service token | 校验 token；返回 `{tid,role,scopes,quota}` |
| POST | `/verify` | service token | body `{token}` |
| POST | `/refresh` | 无 | `{refresh_token}` → 新 access token |
| POST | `/revoke` | bearer（tenant_admin） | `{jti}` |

### Tenants（`/api/v1/tenants`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `` | 列租户 |
| POST | `` | 创建（201） |
| GET | `/{tenant_id}` | 取单个 |
| PATCH | `/{tenant_id}` | 改 display_name/status/plan |
| DELETE | `/{tenant_id}` | 软删除 |

### Members / API keys / Quotas / Audit —— 均在 `/api/v1/tenants/{tenant_id}/...` 下

成员 add-or-create（`POST .../members`）、list/`DELETE`。API key `POST`/`GET`/`DELETE`。配额 `GET`/`PUT`（热更新）。审计 `GET`（`limit` 1..1000，仅自查）。

## 数据库

Postgres 库 `fusion_tenant`。schema 见 [`deploy/sql/schema.sql`](deploy/sql/schema.sql)（附录 A.1 DDL）。9 张表：`tenants`、`users`、`tenant_members`、`api_keys`、`roles`、`quotas`、`usage_ledger`、`audit_log`、`migration_orphans`。首次运行前用 `psql` 应用；`PgStore.ensure_schema` 仅告警（DDL 由操作员/CI 负责）。

附带 `InMemoryStore` 供测试与引导；未注入 Postgres store 时 `build_app()` 用它。

## 测试

```bash
pytest tests/ -v          # 20 用例，离线（InMemoryStore）
pytest tests/ -m integration -v   # 需要在线 Postgres fusion_tenant
ruff check . && ruff format --check .
```

## 部署

```bash
docker build -f deploy/Dockerfile -t fusion-identity:0.1.0 .
docker run -p 11470:11470 \
  -e FUSION_IDENTITY_JWT_KEY=... -e FUSION_IDENTITY_SERVICE_TOKEN=... \
  fusion-identity:0.1.0
```

生命周期由 `start.sh`（`start|stop|restart|status|log`）管理，兼容 fusion-supervisor。

## 运维

完整生产流程——备份/恢复、监控+告警规则、SLO 目标、密钥轮换（KEK + service token + JWT）、HA 前置条件、值班升级——见 **[`docs/ops-runbook.md`](docs/ops-runbook.md)**（英文）。

### 密钥轮换（零停机，双窗口）

**KEK**（加密 IdP `client_secret` + MFA `secret`）——设置 `FUSION_IDENTITY_KEK=<新>` + `FUSION_IDENTITY_KEK_PREV=<旧>`，重启，执行 `POST /api/v1/admin/kek/reencrypt`（service token，`X-Tenant-Id: _system`）扫一遍，再删除 `KEK_PREV` 重启。配置拒绝 `KEK_PREV == KEK` 或 `KEK_PREV == JWT_KEY`（密钥隔离）。

**Service token**（网关 `/verify`、admin、SCIM、usage 上报）——设置 `FUSION_IDENTITY_SERVICE_TOKEN=<新>` + `FUSION_IDENTITY_SERVICE_TOKEN_PREV=<旧>`，重启（两 token 均接受，恒定时间比较），把调用方逐一从旧 token 切到新 token，再删除 `PREV` 重启。配置拒绝 `PREV == 当前` 或 `PREV` < 24 字节。

两种轮换在使用旧（prev）密钥/token 时都打 warning 日志，操作员据此判断轮换是否完成。

### HA 一致性

服务在应用层多实例安全：两个共享同一 Postgres 的实例对租户可见性、jti 签发/吊销、哈希链审计日志、用量聚合均一致（由 `tests/test_ha_consistency.py` 验证，integration 标记）。Postgres HA（流复制 + 故障切换）与 Redis HA 是基础设施前置条件，见 runbook。

## License

MIT
