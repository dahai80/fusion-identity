---
doc_id: fusion-identity/guide
product: fusion-identity
class: core
entry: service
doc_type: guide
title: { zh: "fusion-identity 说明(中文)", en: "fusion-identity overview (Chinese)" }
audience: engineer
status: draft
version: 0.2.28
updated: 2026-11-11
owner: "@dahai"
source_of_truth:
  - README_CN.md
---

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
| `FUSION_IDENTITY_PORT` | 否 | `11470` | 监听端口。经 `fusion_core.config.service_port` 单点解析（config-conventions §2，issue #20）。 |
| `FUSION_REGISTRY` | 否 | `~/fusion/architecture/port-registry.yaml` | 端口注册表路径，用于「先登记后启动」自检（issue #23）。文件缺失时告警并继续（工作区外的独立部署）。 |
| `FUSION_SKIP_REGISTRY_CHECK` | 否 | `0` | 设为 `1` 时跳过注册表自检（未登记端口也放行启动）。 |
| `FUSION_IDENTITY_DATABASE_URL` | 否 | `postgresql://127.0.0.1:5432/fusion_identity` | Postgres 连接串。默认值与生产环境一致，单一权威库（issue #26，DB-2）。 |
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
| `FUSION_IDENTITY_SECRET_GRACE_SECONDS` | 否 | `86400`（24h） | 应用密钥轮换默认宽限窗（issue #28）。窗口内旧版本状态为 `grace`，应用须在窗口内完成解密再加密。 |
| `FUSION_IDENTITY_REGISTRATION_ENABLED` | 否 | `1` | 公开自助注册（issue #39）。`0` 时两个注册端点返回 403。 |
| `FUSION_IDENTITY_EMAIL_VERIFICATION_REQUIRED` | 否 | `1` | 为 `1` 时注册必须提供邮箱并签发一次性验证 token；未验证前登录返回 403。`0` 时注册直接返回 token 对。 |
| `FUSION_IDENTITY_EMAIL_VERIFY_TTL` | 否 | `86400` | 邮箱验证 token 有效期，秒。 |
| `FUSION_IDENTITY_SSO_TICKET_TTL` | 否 | `60` | issue #48：一次性 SSO ticket 有效期，秒（钳制 5–600）。 |
| `FUSION_IDENTITY_PASSWORD_RESET_TTL` | 否 | `3600` | issue #54：密码重置 token 有效期，秒。该 token 是可重置账号密码的 bearer 凭据 —— 请保持较短。 |
| `FUSION_IDENTITY_REGISTRATION_DEFAULT_TENANT` | 否 | `community` | 个人注册自动加入的租户。缺失时在首次个人注册时自动创建（绑定 free 计划模板）。 |
| `FUSION_IDENTITY_SMTP_HOST` | 否 | —（打日志） | SMTP 中继主机。未设置时验证 token 以 WARNING 日志输出（开发兜底，已文档化）而非发信；验证仍阻断登录。 |
| `FUSION_IDENTITY_SMTP_PORT` | 否 | `587` | SMTP 中继端口。 |
| `FUSION_IDENTITY_SMTP_USERNAME` / `_PASSWORD` | 否 | — | SMTP 认证凭据。 |
| `FUSION_IDENTITY_SMTP_FROM` | 否 | — | 验证邮件的发件地址。 |
| `FUSION_IDENTITY_SMTP_STARTTLS` | 否 | `1` | 连接中继时使用 STARTTLS。 |
| `FUSION_IDENTITY_PUBLIC_BASE_URL` | 否 | — | issue #51：认证门户的公网 origin；验证邮件链接构造为 `{base}/auth/?verify={token}`（路由契约以 fusion-gateway `web/auth/app.js` 为准）。未设置 → 相对链接兜底 + 发送时响亮 WARNING。 |

引导仅在租户表为空时运行。租户表**非空**（操作员已带外建好首个 admin，例如通过 `psql`）时跳过引导，无需凭证即可启动。租户表**为空**且未设 `FUSION_BOOTSTRAP_ADMIN_USER`/`PASS` 时，服务**拒绝启动**（fail-closed —— 全新安装必须带外播种首个 admin，否则无人可管理）。

## API

所有租户级路由需 `Authorization: Bearer <jwt>` 与 `X-Tenant-Id: <tid>` 头，token 的 `tid` 必须与二者都匹配。

### Auth（`/api/v1/auth`）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/login` | 无 | `{username,password,tenant_id?}` → `{access_token,refresh_token,...}`。issue #39：邮箱未验证的用户返回 403（`email not verified — check your inbox for the verification link`），不签发 token。issue #47：`tenant_id` 可选——省略时在密码校验通过后从用户成员关系解析（单一活跃成员关系 → 该租户；多个 → 409 `{error:"tenant_ambiguous",tenants:[{tenant_id,display_name}]}` 供前端弹出选择器；无 → 与错误凭据相同的 `invalid credentials`）。显式 `tenant_id` 仍优先；凭据正确但不属于该租户返回 401 `tenant_mismatch`（区别于 `invalid credentials`）。 |
| GET | `/verify?token=` | service token | 校验 token；返回 `{tid,role,scopes,quota}` |
| POST | `/verify` | service token | body `{token}` |
| POST | `/refresh` | 无 | `{refresh_token}` → 新 access token |
| POST | `/ticket` | bearer | issue #48：签发一次性 SSO ticket（`fsso_…`，TTL `FUSION_IDENTITY_SSO_TICKET_TTL` 默认 60 秒，钳制 5–600），绑定会话的 sub + 租户，用于 fusion-site → web-shell 免二次登录交接。返回 `{ticket,expires_in}`；落库仅存 sha256 哈希。 |
| POST | `/ticket/exchange` | 无（ticket 即凭据） | issue #48：`{ticket}` → 标准 `{access_token,refresh_token,…}`。原子单次使用（重放 → 401 `invalid ticket`）；兑换时从 tenant_members 重新取角色并复核成员关系/租户状态（fail-closed）。与 login 相同的限流。 |
| POST | `/password/forgot` | 无 | issue #54：`{email}` → 请求密码重置。**恒返回** `{sent:true}` —— 账号是否存在不由此端点泄露（防枚举）。账号存在时，一次性带过期 token（sha256 落库，TTL `FUSION_IDENTITY_PASSWORD_RESET_TTL` 默认 1 小时）以 `{FUSION_IDENTITY_PUBLIC_BASE_URL}/auth/reset?token={token}` 邮件发出。有限流。 |
| POST | `/password/reset` | 无（token 即凭据） | issue #54：`{token,new_password}` → 消费一次性 token（原子，重放/过期/未知 → 统一 400），轮换 argon2id 哈希，撤销全部 refresh token 家族（旧会话全部失效），审计 `auth.password_reset` 记入 `_system`。密码策略强制（≥10 字符，含字母 + 数字）。 |
| POST | `/revoke` | bearer（tenant_admin） | `{jti}` |

### 公开注册（`/api/v1/auth/register*` —— issue #39）

自助注册通道（设计文档：`architecture/fusion-site-auth-1104.md`）。两者均豁免租户中间件、有限流、有审计（`auth.registered` / `auth.tenant_registered` / `auth.email_verified` 记入租户 `_system`），且是对既有创建内部（`create_user` / `provision_core`）的薄封装 —— 不存在第二条用户/租户创建代码路径。issue #51：邮件验证链接为 `{FUSION_IDENTITY_PUBLIC_BASE_URL}/auth/?verify={token}`（认证门户契约）；API 兑换端点仍为 `POST /api/v1/auth/verify-email`（原始 token）。

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/register` | 无 | 通道 A —— 个人注册。`{username,password,display_name?,email?}`。创建全局用户，自动加入 `FUSION_IDENTITY_REGISTRATION_DEFAULT_TENANT`（缺失时首次注册自动创建并绑定 free 计划模板），角色 `member` —— 但触发自动建租户的**首个注册者**为 `tenant_admin`，保证 open-join 社区永无“无管理员”状态（issue #63；后续加入者仍为 `member`；存量无管理员租户可用 `POST /api/v1/admin/tenants/{id}/admins` 补救）。验证开启时：邮箱必填（否则 422），响应为 `{status:"verification_required"}`，`/verify-email` 完成前登录保持 403。验证关闭时：立即返回可用 `tokens`。用户名冲突 409；邮箱重复 409（issue #53 —— 大小写不敏感；此前表现为原始 500）；`FUSION_IDENTITY_REGISTRATION_ENABLED=0` 时 403。 |
| POST | `/register-tenant` | 无 | 通道 B —— 租户注册。`{tenant_display_name,admin_username,admin_password（≥12）,admin_email?,plan?="free"}`。封装 `provision_core`（与管理员开通路径相同的 store 方法：租户 + 计划配额模板 + 种子 admin，自动激活，支持 `Idempotency-Key` 重放）。admin 密码绝不回显。admin 用户名或邮箱重复 409（issue #53，在租户创建前预检）。返回开通结果 + 立即的 `tokens` 对（注册请求本身已出示凭据；后续登录仍需验证）。issue #66：种子 admin 以 `email_verified=True` 创建 —— 特权创建路径绝不因验证邮件无法送达而把 admin 锁在门外；验证开启时注册后立即二次登录也成功。 |
| POST | `/verify-email` | 无 | `{token}` → 一次性、带过期的兑换（哈希落库、按哈希查找、成功后清列使重放返回 400）。无效/过期/重放一律 400 且不区分（防枚举）。 |
| POST | `/verify-email/resend` | 无 | `{username}` → 重新签发（旧 token 失效）并重发。**故意公开** —— 未验证用户没有 bearer token，bearer 门控的重发会死锁。无论账号是否存在/状态如何，统一返回 `{resent:bool}`（防枚举）。 |

**邮件投递**：`FUSION_IDENTITY_SMTP_HOST` 未设置时，验证 token 以 WARNING 日志输出（开发兜底）而非发信；验证仍阻断登录。SMTP 发送失败不使注册失败 —— 重发端点负责重试。

### 密码找回（`/api/v1/auth/password/*` —— issue #54）

为丢失密码的用户提供自助重置（此时不存在可用的 bearer token）。两个端点均豁免租户中间件且有限流。安全姿态：请求端点响应统一（无论账号是否存在均返回 `{sent:true}` —— 防枚举）；重置 token 为 `secrets.token_urlsafe(32)`，仅存 sha256，单次使用（在 UPDATE 内原子消费），带过期（TTL `FUSION_IDENTITY_PASSWORD_RESET_TTL` 默认 1 小时），仅经邮件传递；重置成功即轮换密码哈希并撤销全部 refresh token 家族。未知/过期/重放 token 一律返回同一 400。SMTP 未设置时的开发兜底与验证邮件一样输出重置链接日志。

### 租户加入策略（`join_policy` —— issue #40）

每个租户带一个管理员可设的 `join_policy`（默认 `invite`；在租户 create/PATCH、admin create/PUT、开通 API 上均可设置；自动创建的公开 `community` 租户使用 `open`）：

| 策略 | 流程 |
|---|---|
| `invite` | tenant_admin 签发一次性、带过期的邀请 token（预指派角色，`finv_` 前缀，sha256 落库，原文只显示一次）；持有 bearer 的用户兑换 |
| `proof` | 既有 `POST /members/by-proof` —— 保持不变 |
| `approval` | 用户提交加入请求；tenant_admin 批准（批准即入会，角色 `member`）或拒绝；被拒后可重新申请 |
| `open` | 用户自助加入，角色**强制**为 `member` |

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/api/v1/tenants/{tid}/invites` | `tid` 的 tenant_admin | `{role?="member", email?, ttl_seconds?(60..2592000, 默认 7 天)}` → `{invite_id, token（原文，仅此一次）, role, expires_at}`。审计 `member.invited`。 |
| GET | `/api/v1/tenants/{tid}/invites` | `tid` 的 tenant_admin | 清单；token 哈希不出库。 |
| POST | `/api/v1/auth/invites/redeem` | bearer | `{token}` → 以预指派角色加入该租户。单次使用 + 过期由 store 原子执行；无效/过期/重放一律 400。审计 `member.joined`。 |
| POST | `/api/v1/auth/tenants/{tid}/join` | bearer | open 自助加入；租户 `join_policy` 非 `open` 时 403；角色强制 `member`；已是成员 409。有限流。审计 `member.self_added`。 |
| POST | `/api/v1/tenants/{tid}/join-requests` | bearer | 提交（策略非 `approval` 时 403；重复 pending 409；被拒后可重新申请）。有限流。审计 `join.requested`。 |
| GET | `/api/v1/tenants/{tid}/join-requests` | `tid` 的 tenant_admin | 列表，可选 `?status=pending\|approved\|rejected`。 |
| POST | `/api/v1/tenants/{tid}/join-requests/{rid}/approve` \| `/reject` | `tid` 的 tenant_admin | 裁决（仅 pending 可裁决，否则 409）。批准即授予角色 `member` 的成员资格。审计 `join.approved` / `join.rejected`。 |

迁移 `0018_join_policy.sql`：`tenants.join_policy`（默认 `invite`）+ `tenant_invites` + `join_requests` 表。

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
- `DELETE /sessions`（service token，issue #29）：`{sub, tenant_id}` → `{revoked_access_jtis, revoked_refresh_tokens}`。用户删除流程：吊销该主体全部未过期 access/session jti 及所有 refresh-token family —— 凭证立即失效，而非等自然过期。未知租户 → 404；幂等；写审计。

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

### 应用密钥 — 业务应用密钥签发（issue #28）

按 `business/AGENTS.md` 硬约束 #1：业务应用只消费三个 env 变量，任何额外密钥材料由 identity 签发（禁止 `.env` 塞密钥）。首个消费者是 `ai-assistant-agent` TokenStore 的 KEK。

三个路由均由 service token 门控（跨租户平面，`X-Tenant-Id: _system`）。原始密钥材料（`fms_` 前缀）**只返回一次**；identity 只存 SHA-256 哈希 —— 与 API key 同等落盘纪律。轮换时旧版本降级为宽限窗；应用须在窗口内完成数据解密再加密，窗口过后旧版本状态读回 `expired`。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/apps/{app_id}/secrets` | 签发 v1（已有 current 版本则 409，改用 rotate）。可选 body `{"grace_seconds"?}`。返回 `{secret_id, version, secret, previous_version}`。 |
| GET | `/api/v1/apps/{app_id}/secrets` | 按版本倒序列出 —— `{secret_id, version, status, prefix, created_at, grace_until}`，绝不返回密钥材料。 |
| POST | `/api/v1/apps/{app_id}/secrets/rotate` | 生成新 current 版本；旧版本降级为 `grace`（应用无密钥则 404）。 |
| DELETE | `/api/v1/apps/{app_id}/secrets/{version}` | 立即将某版本标记 `revoked`（issue #35，UC-S3）—— 密钥确认泄露时提前切断宽限窗。版本不存在则 404。审计 `app_secret.revoked`。 |

### Admin Console 聚合读（issue #35，DC-3）

fusion-security Admin Console 是服务，只持有 service token（union-web iframe 不持有用户 JWT），因此为其增加 service token 门控的只读聚合端点（数据源侧 RBAC 仍为权威，不新增任何变更面）：

- `GET /api/v1/admin/tenants/{tenant_id}/members/summary` —— 成员区卡片计数：`{total, active, disabled, locked, by_role}`，只有计数，无用户名/邮箱；租户不存在 404。
- `GET /api/v1/admin/tenants/{tenant_id}/idps/summary` —— SSO 能力状态：`{configured, count, types, auto_provision}`，绝不返回 `client_secret` 材料；租户不存在 404。
- `GET /api/v1/admin/app-secrets` —— 跨应用密钥清单：`{apps: [{app_id, versions, current_version, status, created_at, grace_until}]}`，每应用一行，无任何密钥材料。

`app_id` 须匹配 `^[a-z0-9][a-z0-9_-]{0,63}$`。每次签发/轮换都写入哈希链审计账本（`app_secret.issued` / `app_secret.rotated`，租户 `_system`）。`app_secrets` 为平台级表（无 `tenant_id`、无 RLS —— service token 平面，与 `plan_templates` 同信任级）；迁移 `0013_app_secrets.sql`。

### SaaS 凭据 —— 供 provider 层存取（issue #34）

第三方 SaaS API key（如 VTON 服务商）是**外部签发**的 —— identity 无法凭空轮换出有效新 key，且消费者必须能在启动时和 SaaS 侧换 key 后（401/403 触发一次重拉 + 一次重试，应用侧去抖）取回原始值。因此与 `app_secrets`（SHA-256 哈希、明文只给一次）不同，这类值以 **KEK 下 AES-256-GCM 加密**落盘，可按需取回。

全部路由由 service token 门控（`X-Tenant-Id: _system`）。`app_id` 匹配 `^[a-z0-9][a-z0-9_-]{0,63}$`，凭据 `name` 匹配 `^[a-z0-9][a-z0-9_.-]{0,63}$`。每次存/取都写入哈希链审计账本（`app_credential.stored` / `app_credential.fetched`，租户 `_system`）；原始值绝不写日志、绝不入审计。`app_credentials` 为平台级表（无 `tenant_id`、无 RLS）；迁移 `0016_app_credentials.sql`。

| 方法 | 路径 | 说明 |
|---|---|---|
| PUT | `/api/v1/apps/{app_id}/credentials/{name}` | 操作员存入/覆盖原始凭据（upsert —— 重放 PUT 即第三方 key 的轮换路径）。body `{"value": "..."}`。只返回元数据，不回显值。 |
| GET | `/api/v1/apps/{app_id}/credentials/{name}` | 消费方取回当前原始值（未存过则 404）。累加 `fetch_count` / `last_fetched_at`，用于异常检测。 |

预期消费模式（ai-trysuite §8.2）：启动时拉取、仅存内存；SaaS 返回 401/403 时重拉一次并重试一次；批量重拉由应用侧去抖（`saas_key_refresh_cooldown:{provider}`，TTL 5 分钟）。密文损坏/KEK 不匹配时显式返回 HTTP 500（属运维事故，非 404）。KEK 轮换期间，重加密清扫完成前取回路径经 `FUSION_IDENTITY_KEK_PREV` 解密。

### 新业务服务的凭据签发流程

两个平面，按**谁生成密钥**选择 —— 绝不在 `.env` 里塞密钥：

| 密钥来源 | 平面 | 流程 |
|---|---|---|
| identity 生成（HMAC 密钥、需与服务及第三方共享的 webhook 签名密钥） | credentials（issue #34） | 操作员生成一次（`openssl rand -hex 32`），携带 service token `PUT /api/v1/apps/{app_id}/credentials/{name}`，在第三方控制台配置同一值；消费者启动时 `GET` 取回。 |
| 第三方签发（provider API key、OAuth client secret） | credentials（issue #34） | 操作员携带 service token 一次性 `PUT` 真实值；消费者启动时 `GET`，401/403 时重拉。 |
| 服务本地自生成（仅该服务自己读取的原始材料，如落盘 KEK） | app_secrets（issue #28） | `POST /api/v1/apps/{app_id}/secrets`；原始 `fms_` 值只返回一次 —— 消费者须在接收时持久化（如 0600 文件）。 |

隔离：identity 为唯一权威；`app_id` 是凭据名的命名空间边界（`/api/v1/apps/{app_id}/credentials/{name}`），消费者之间不共享扁平中心命名空间。`FUSION_<APP>_DATA_DIR` 的 0600 文件最多是本地缓存，绝不是权威。注意 service token 本身是平台级凭据 —— 按 app 的隔离靠 `app_id` 命名，而非按 app 的 token 作用域；泄漏时轮换 token（支持 `FUSION_IDENTITY_SERVICE_TOKEN_PREV` 双窗口）。

## 数据库

Postgres 库 `fusion_identity` —— 单一权威库（issue #26，DB 规范 DB-2：一应用一库；旧 `fusion_tenant` 默认值已废弃）。schema 见 [`deploy/sql/schema.sql`](deploy/sql/schema.sql)（附录 A.1 DDL），`PgStore` 启动时经 [`migrations/`](migrations/) 幂等应用。24 张表：`tenants`、`users`、`tenant_members`、`api_keys`、`roles`、`quotas`、`usage_ledger`、`tenant_usage_daily`、`refresh_tokens`、`revoked_jtis`、`issued_jtis`、`audit_log`、`migration_orphans`、`identity_providers`、`user_mfa`、`lease_log`、`departments`、`custom_roles`、`role_menu_matrix`、`known_menus`、`plan_templates`、`idempotency_keys`、`event_outbox`、`app_secrets`、`app_credentials`。`PgStore.ensure_schema` 仅告警（DDL 由操作员/CI 负责）。

附带 `InMemoryStore` 供测试与引导；未注入 Postgres store 时 `build_app()` 用它。

### 旧库 `fusion_tenant` 退役（issue #26）

曾在旧默认库 `fusion_tenant` 上运行过的部署，需先把数据合并进 `fusion_identity` 再删旧库。本机 `fusion_tenant` 为零行，以下归档仅为安全网：

```bash
# 1. 归档旧库（custom-format dump，恢复到临时库验证）
pg_dump -Fc -Z 6 -f /Users/dahai/db-archive/fusion_tenant_$(date +%F).dump \
    "postgresql://127.0.0.1:5432/fusion_tenant"
createdb fusion_tenant_verify
pg_restore -d fusion_tenant_verify /Users/dahai/db-archive/fusion_tenant_YYYY-MM-DD.dump
# 2. 逐表核对行数，缺失行合并进 fusion_identity，再删临时库与旧库：
dropdb fusion_tenant_verify
dropdb fusion_tenant
```


## 测试

```bash
pytest tests/ -v          # 20 用例，离线（InMemoryStore）
pytest tests/ -m integration -v   # 需要在线 Postgres fusion_identity
ruff check . && ruff format --check .
```

## 部署

```bash
docker build -f deploy/Dockerfile -t fusion-identity:0.1.0 .
docker run -p 11470:11470 \
  -e FUSION_IDENTITY_JWT_KEY=... -e FUSION_IDENTITY_SERVICE_TOKEN=... \
  fusion-identity:0.1.0
```

生命周期由 `start.sh`（`start|stop|restart|status|log|registry-check`）管理，兼容 fusion-supervisor。

绑定前，`start` 会执行**「先登记后启动」自检**（issue #23，config Phase 3.3）：确认监听端口已在 `port-registry.yaml` 中登记给 `fusion-identity`，若条目缺失或端口不符则**拒绝启动** —— 让未登记端口在启动时即失败，而不是拖到 CI `check-ports` 才暴露。`FUSION_SKIP_REGISTRY_CHECK=1` 可跳过自检；注册表文件缺失时告警并继续（独立部署）。`./start.sh registry-check` 可单独运行该检查。

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
