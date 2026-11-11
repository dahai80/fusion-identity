---
doc_id: fusion-identity/get-started
product: fusion-identity
class: core
entry: service
doc_type: get-started
title: { zh: "fusion-identity 快速上手", en: "fusion-identity quick start" }
audience: engineer
status: draft
version: 0.2.28
updated: 2026-11-11
owner: "@dahai"
source_of_truth:
  - README.md
  - start.sh
  - pyproject.toml
---

# fusion-identity 快速上手 / Quick start

fusion-identity 是 Fusion 生态唯一的 JWT 签发方与租户注册中心。本文覆盖从安装到第一次登录验证的最短路径。

fusion-identity is the sole JWT issuer and tenant registry for the Fusion ecosystem. This page covers the shortest path from install to a verified login.

## 前置条件 / Prerequisites

- Python >= 3.12,共享 venv `~/fusion/.venv`
- Postgres(默认 `postgresql://127.0.0.1:5432/fusion_identity`)
- Redis(可选;不设置则缓存/并发租约/gRPC 平面关闭,仅 REST 模式)

## 安装 / Install

```bash
cd /Users/dahai/fusion
source .venv/bin/activate
pip install -e fusion-identity
```

## 必需环境变量 / Required environment

服务 fail-closed:缺任一变量直接拒绝启动(start.sh 退出码 2)。

The service is fail-closed: it refuses to start when any of these is missing.

```bash
export FUSION_IDENTITY_JWT_KEY="$(openssl rand -hex 32)"        # >= 32 bytes, HS256 signing key
export FUSION_IDENTITY_SERVICE_TOKEN="$(openssl rand -hex 24)"  # >= 24 bytes, gates /verify + admin plane
export FUSION_IDENTITY_KEK="$(openssl rand -hex 32)"            # must differ from JWT_KEY
export FUSION_BOOTSTRAP_ADMIN_USER=admin
export FUSION_BOOTSTRAP_ADMIN_PASS=adminpass                    # >= 12 chars; required on a fresh (empty) tenant table
```

约束 / Constraints:

- `FUSION_IDENTITY_KEK` 不得等于 `FUSION_IDENTITY_JWT_KEY`(start.sh 显式校验)。
- `FUSION_BOOTSTRAP_ADMIN_PASS` 设置时必须 >= 12 字符;租户表为空且未设置引导管理员时启动即拒绝。
- Bootstrap 仅在租户表为空时执行;表非空(已手工播种)则跳过。

## 启动与验证 / Start and verify

```bash
./fusion-identity/start.sh start
curl -s http://127.0.0.1:11470/health   # {"status":"ok","service":"fusion-identity",...}
curl -s http://127.0.0.1:11470/ready    # readiness: store + redis; 503 on failure
```

`start.sh` 在绑定端口前执行 register-then-start 自检:端口必须在 `~/fusion/architecture/port-registry.yaml` 中登记为 fusion-identity,否则拒绝启动(`FUSION_SKIP_REGISTRY_CHECK=1` 可旁路;注册表文件缺失仅告警)。

默认仅绑定 `127.0.0.1`(PRD C8:不直接对外暴露,外部流量经 fusion-gateway)。

## 第一次登录 / First login

```bash
curl -s -X POST http://127.0.0.1:11470/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"adminpass"}'
```

返回 `{access_token, refresh_token, ...}`。携带 token 调用租户接口时必须同时带 `Authorization: Bearer <jwt>` 与 `X-Tenant-Id: <tid>`,且两者 `tid` 必须一致。

## 下游服务验证 token / Verify a token (service-to-service)

```bash
curl -s -X POST http://127.0.0.1:11470/api/v1/auth/verify \
  -H "Authorization: Bearer $FUSION_IDENTITY_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"token":"<access_token>"}'
```

返回 `{tid, role, scopes, quota, tenant_status}`。下游服务不要再自建 JWT 校验——统一走该端点。

## 生命周期 / Lifecycle

```bash
./fusion-identity/start.sh {start|stop|restart|status|log [-f]|registry-check|compose {up|down|logs}}
```

日志与 PID 文件默认在 `~/.fusion-identity/`(可用 `FUSION_IDENTITY_LOG_FILE` / `FUSION_IDENTITY_PID_FILE` 覆盖)。

## 运行测试 / Tests

```bash
pytest tests/ -v                  # 219 offline cases (InMemoryStore + fakeredis)
pytest tests/ -m integration -v   # 15 cases: needs live Postgres + Redis
```

## 下一步 / Next steps

- 全部端点: [api-reference.md](api-reference.md)
- 全部环境变量: [config-reference.md](config-reference.md)
- 生产运维(备份/轮换/SLO): [docs/ops-runbook.md](ops-runbook.md)
