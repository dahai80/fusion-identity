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
| `FUSION_IDENTITY_WEBHOOK_URL` | 否 | —（关闭） | 生命周期事件 outbox 的出站 webhook 端点（issue #14）。必须同时设置 `FUSION_IDENTITY_WEBHOOK_SECRET`，否则拒绝启动（fail-closed）。不设 = 仅拉模式（轮询 `GET /api/v1/admin/events`）。 |
| `FUSION_IDENTITY_WEBHOOK_SECRET` | 否 | — | webhook + 开通后钩子负载的 HMAC-SHA256 签名密钥（`X-Fusion-Signature: sha256=<hex>`）。 |
| `FUSION_IDENTITY_WEBHOOK_TICK` | 否 | `5` | webhook worker 轮询间隔，秒。 |
| `FUSION_IDENTITY_WEBHOOK_MAX_ATTEMPTS` | 否 | `5` | 投递尝试次数上限，超过后事件进入死信（`status=dead`，仍在 outbox 可查）。 |

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

### 会话 token（`/api/v1/auth/session` —— Union Web R-2，issue #9）

网关为本地浏览器会话签发的 session token（单租户 local 模式，fusion-web-shell 不自带鉴权，浏览器不直连 identity）。service token 鉴权：

- `POST /session`：`{sub?="web-shell", tenant_id?="local", role?="member", ttl_seconds?(60..86400，默认 43200)}` → `{access_token,jti,expires_in,role}`。`local` 租户首次使用时幂等自建；其他租户必须已存在且 active（fail-closed）。
- `POST /session/verify`：`{token}` → `{valid,sub,tid,tenant,role,scope,iat,exp,jti,type}`，校验签名/`type=session`/jti 吊销/租户状态。

claims 预留（`tid`/`tenant` 固定为 `local`），后续多租户扩展无需改 token 格式。session token 不能通过 `/verify`、`/introspect` 校验（type 不匹配）。

### 企业管理契约（issue #10）

- **部门**：`/api/v1/tenants/{tid}/departments` CRUD（`{name,parent_id?,tool_allowlist:[...]}`），tenant_admin + 路径守卫，供管理台消费。
- **用量汇总**：`GET .../usage/summary` → `{events,totals{metric},by_source,by_model}`。
- **审计事件接入**：`POST .../audit/events`（service token），下游推送审批/权限/运行事件，动作名归一为 `external.*`，写入哈希链审计账本。
- **OTLP 导出**：`GET .../audit/otlp`（tenant_admin 或 service token），OTLP/JSON logs 格式，供本地 OTel Collector 接 SIEM，完全离线/内网可用。

### 业务应用审计事件 API（issue #18）— `/api/v1/tenants/{tenant_id}/audit/...`

领域应用（如 ai-speech-exam 的 AI 调用、专家审批/驳回、人工改分）把审计事件追加进 identity 的哈希链账本 —— 防篡改证据留在 identity，业务应用不自建链。

- **追加事件**：`POST .../audit/business-events`（service token）。必填字段：`actor`、`action`、`object_id`、`trace_id`、`timestamp`（unix epoch，允许 ±5 分钟时钟偏差），外加模式自由的 `payload` 与可选 `severity`。动作名归一为 `external.*`；`actor`→`user_id`、`object_id`→`resource`，其余进哈希覆盖的 `detail` JSONB。返回 `{seq, chain_hash, action, ts, trace_id}`。
- **合规查询**：`GET .../audit/business-events`（tenant_admin，audit 读权限），支持 `?actor=&action=&object_id=&trace_id=&since=&until=&limit=1..1000` 组合过滤，返回 `{events, count, truncated}`；内部（非业务）审计行不会混入。
- **合规导出**：`GET .../audit/export`（tenant_admin 或 service token），一次往返返回账本切片（`?since=&until=&limit=`）加链校验结论：`{tenant_id, generated_at, chain:{valid,broken_at}, count, events}`。

Postgres：迁移 `0011_business_audit_gin.sql` 为 `audit_log.detail` 加 GIN 索引（`jsonb_path_ops`），trace_id/actor/object_id 过滤走索引。

### RBAC 契约 — 自定义角色 + write class + 菜单矩阵（issue #12，迁移 E5）

将固定四角色模型通用化为每租户 RBAC 契约，供管理台（fusion-web-shell）原样承载 Users & Roles 页面。内置角色（`tenant_admin`/`operator`/`member`/`viewer`）不可变，其 write class 由权限种子确定性推导（种子中有 `write` 动作的资源即一个 write class）。自定义角色按租户隔离（每租户 ≤64 个，每个 ≤64 个 write class），授予的 write class 与能力脊柱（capability spine）的变更门控相交。

**角色 ↔ 菜单矩阵**是运行时可编辑策略：菜单由模块 manifest 声明、按租户注册，identity 只存 (tenant, role) 矩阵行。变更在下一次 `POST /api/v1/auth/verify`（下次页面加载）即生效，无需前端发版；`POST .../roles/{role_id}/menus/reset` 恢复内置默认。

`verify` 响应是执行面，现同时携带 `write_classes` + `allowed_menus`（与 `role`/`scopes` 并列），shell 与网关做服务端执行——绝不仅靠前端。成员的角色无法解析（自定义角色被删）时 verify 直接 fail-closed。**审批人 ≠ 申请人**不变量成为一等契约端点。

| Method | Path | Auth | 说明 |
|---|---|---|---|
| GET | `.../roles` | tenant_admin（路径守卫） | 列出内置 + 自定义角色（含 `write_classes` 与当前 `menus`） |
| POST | `.../roles` | tenant_admin（路径守卫） | 创建自定义角色 `{role_id,display_name,write_classes}`；与内置冲突 → 409 |
| PATCH | `.../roles/{role_id}` | tenant_admin（路径守卫） | 更新自定义角色；内置 → 403 |
| DELETE | `.../roles/{role_id}` | tenant_admin（路径守卫） | 删除自定义角色；内置 → 403，仍有成员使用 → 409 |
| GET | `.../roles/{role_id}/menus` | tenant_admin（路径守卫） | 当前矩阵行（未设置时为默认） |
| PUT | `.../roles/{role_id}/menus` | tenant_admin（路径守卫） | 设置矩阵行 `{menus:[...]}`；未注册菜单 → 409 |
| POST | `.../roles/{role_id}/menus/reset` | tenant_admin（路径守卫） | 重置为默认 |
| GET | `.../menus` | tenant_admin（路径守卫） | 本租户已注册菜单 id |
| POST | `.../menus` | tenant_admin（路径守卫） | 注册菜单 id `{menus:[...]}`（每租户 ≤256） |
| POST | `.../approvals/validate` | tenant_admin（路径守卫） | `{requester_id,approver_id}` → 200 `{valid:true}`；相同 → 403，非成员 → 404 |

用户的角色分配 / 启用 / 禁用 / 重置密码仍在 members 平面（`/api/v1/tenants/{tid}/members...`）；角色校验现在接受任何可解析角色（内置或本租户自定义），store 是唯一 fail-closed 权威。成员角色守卫（不可降级/禁用/移除最后一个 `tenant_admin`、不可改自己角色）不变，同样作用于自定义角色路径。

Schema：`custom_roles`、`role_menu_matrix`、`known_menus`（迁移 `0009_rbac_custom_roles.sql`，与其他租户表一致启用 RLS）。

### 权限点 — 按角色矩阵真实执行（issue #16）

每条租户内路由通过 `deps.py` 的 `require_permission[_of]` 依赖工厂声明显式 `(resource, action)` 权限点；store 是权威（内置矩阵 `BUILTIN_ROLE_MATRIX` 在 `store.py`，自定义角色经其 `write_classes` 解析）。**默认拒绝**：矩阵中无该资源条目的角色一律 403 —— `idps`/`rbac` 无非管理员行，仅 `tenant_admin` 可用。自定义角色当其 write class 含 `{resource}:write` 时获得该资源全部动作（write 蕴含 read/delete），否则无任何权限。跨租户守卫（token `tid` 与 `X-Tenant-Id`、路径三方一致）不变。

内置角色执行矩阵（`r` = 读/GET，`w` = 写/POST/PUT/PATCH，`d` = 删/DELETE）：

| 资源（路由） | viewer | member | operator | tenant_admin |
|---|---|---|---|---|
| `tenants` — `GET /tenants...`、`PATCH /tenants/{id}` | r | r | r | r w |
| `members` — `.../members...` | — | — | r | r w d |
| `api_keys` — `.../api-keys...` | — | — | r w d | r w d |
| `quotas` — `.../quotas` | r | r | r | r w |
| `audit` — `.../audit...` | — | — | r | r |
| `usage` — `.../usage`、`/usage/summary`、`/config`、`/export` | r | r | r | r |
| `departments` — `.../departments...` | r | r w | r w d | r w d |
| `idps` — `.../idps...` | — | — | — | r w d |
| `rbac` — `.../roles...`、`.../menus...`、`.../approvals/validate` | — | — | — | r w d |

自助路由（`POST /api/v1/auth/password`、`logout`、`revoke`、全部 `/api/v1/auth/mfa`）为任意已认证用户（仅操作本人）。admin/provisioning 平面保持 service token 门控。矩阵 + 默认拒绝由 `tests/test_rbac_matrix.py` 断言（每类路由逐角色 200/403 + 守卫清单测试证明零隐式可访问的租户内路由）。

### 租户开通自动化 — 一次性开通 + 生命周期事件（issue #14，迁移 `0010_provisioning.sql`）

面向 SaaS 控制面（首个消费者 CharacterVoiceAgent）的一次性租户开通，取代过去 3+ 个无事务保证、无事件的分散 admin 调用。

**一次性开通（M-A）**：`POST /api/v1/admin/tenants/provision`（service token 门控）。单次调用完成：租户 + 按套餐映射的配额 + 种子管理员 + API key。请求体 `{tenant_id?, display_name, plan, quotas?, seed_admin?{username, password?}, api_key?{scopes}, hook_url?}` —— `tenant_id` 省略则自动生成；`seed_admin.password` 省略则生成随机密码（仅返回一次，`must_change_password=true`）；原始 `fmu_` key 仅出现在响应（及签名钩子负载）中，绝不进 outbox 事件。

**幂等**：带 `Idempotency-Key` 头重放同一 key 返回原始结果（`idempotent_replay: true`），不产生重复租户。种子管理员用户名在建租户前预检，冲突不会留下半开通的孤儿租户。

**套餐配额模板（M-C）**：`plan` 确定性映射配额模板，内置 `free`/`starter`/`standard`/`pro`/`enterprise`；生效配额 = 模板 + 每租户覆盖。运行时管理：`GET/PUT /api/v1/admin/plan-templates[/{plan}]`。注意 `tpm` 字段是**每日 token 上限**（历史字段名，gRPC 面按日计数器执行）。

**生命周期事件（M-B）**：所有生命周期变更写入事务性事件 outbox（`event_outbox` 表）：`tenant.created`、`tenant.quota_changed`、`tenant.status_changed`、`apikey.created`、`apikey.revoked`。
- 拉模式：`GET /api/v1/admin/events?cursor=<seq>&limit=100`，返回 `next_cursor` 增量轮询。
- 推模式：设置 `FUSION_IDENTITY_WEBHOOK_URL` + `SECRET` 后后台 worker 以 HMAC-SHA256 签名（`X-Fusion-Signature`，及 `X-Fusion-Event`/`X-Fusion-Event-Id` 头）投递；失败按 tick 重试，超过上限进入死信（可查可重放）。

**开通后钩子（M-D，可选）**：请求带 `hook_url` 时，identity 向该 URL POST `{"event": "provision.completed", "data": {tenant, quota, admin, api_key}}`（同一 HMAC 签名）。控制面可直接从负载把租户 key 注册进 fusion-gateway 等下游 —— 无需轮询，identity 内无任何网关专用代码。

## 数据库

Postgres 库 `fusion_tenant`。schema 见 [`deploy/sql/schema.sql`](deploy/sql/schema.sql)（附录 A.1 DDL），`PgStore` 启动时经 [`migrations/`](migrations/) 幂等应用。23 张表：`tenants`、`users`、`tenant_members`、`api_keys`、`roles`、`quotas`、`usage_ledger`、`tenant_usage_daily`、`refresh_tokens`、`revoked_jtis`、`issued_jtis`、`audit_log`、`migration_orphans`、`identity_providers`、`user_mfa`、`lease_log`、`departments`、`custom_roles`、`role_menu_matrix`、`known_menus`、`plan_templates`、`idempotency_keys`、`event_outbox`。`PgStore.ensure_schema` 仅告警（DDL 由操作员/CI 负责）。

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
