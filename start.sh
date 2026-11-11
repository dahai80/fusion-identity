#!/usr/bin/env bash
set -euo pipefail

# fusion-identity lifecycle script — fusion-supervisor compatible.
# Usage: ./start.sh start|stop|status|log|restart

SERVICE_NAME="fusion-identity"
DEFAULT_HOST="127.0.0.1"
DEFAULT_PORT="11470"
PID_FILE="${FUSION_IDENTITY_PID_FILE:-$HOME/.fusion-identity/identity.pid}"
LOG_FILE="${FUSION_IDENTITY_LOG_FILE:-$HOME/.fusion-identity/identity.log}"
VENV_DIR="${FUSION_IDENTITY_VENV:-/Users/dahai/fusion/.venv}"
# Issue #64: persist the required env to a 0600 file so ./start.sh restart
# works from a clean shell (the 2026-11-10 stall incident could not be
# restarted because the env lived only in the launching shell). Sourced
# before the fail-closed checks on every invocation; written on every
# successful start. Supervisor-managed deploys can point
# FUSION_IDENTITY_ENV_FILE at the supervisor env file instead.
ENV_FILE="${FUSION_IDENTITY_ENV_FILE:-$HOME/.fusion-identity/env}"
if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
fi

# Issue #71: the enforcement plane (redis-backed api-key cache, daily-quota
# counters, ConcurrencyManager leases, embedded gRPC AuthorizeAndAcquire) is
# ON by default — quota values without enforcement are dead letters. Opt out
# per deploy by exporting FUSION_IDENTITY_REDIS_URL="" (set-but-empty); the
# ${VAR+set} test distinguishes empty from unset. GRPC_PORT 0 disables gRPC
# explicitly. 50051 is the registered fusion-identity-grpc port.
if [ "${FUSION_IDENTITY_REDIS_URL+set}" != "set" ]; then
    export FUSION_IDENTITY_REDIS_URL="redis://127.0.0.1:6379/0"
fi
if [ "${FUSION_IDENTITY_GRPC_PORT+set}" != "set" ]; then
    export FUSION_IDENTITY_GRPC_PORT="50051"
fi

if [ -z "${FUSION_IDENTITY_JWT_KEY:-}" ]; then
    echo "ERROR: FUSION_IDENTITY_JWT_KEY unset — service refuses to start (fail-closed)" >&2
    exit 2
fi
if [ -z "${FUSION_IDENTITY_SERVICE_TOKEN:-}" ]; then
    echo "ERROR: FUSION_IDENTITY_SERVICE_TOKEN unset — verify endpoint would be unprotected" >&2
    exit 2
fi
if [ -z "${FUSION_IDENTITY_KEK:-}" ]; then
    echo "ERROR: FUSION_IDENTITY_KEK unset — must not reuse JWT signing key (fail-closed)" >&2
    exit 2
fi
if [ "${FUSION_IDENTITY_KEK}" = "${FUSION_IDENTITY_JWT_KEY}" ]; then
    echo "ERROR: FUSION_IDENTITY_KEK equals FUSION_IDENTITY_JWT_KEY — key isolation required" >&2
    exit 2
fi

mkdir -p "$(dirname "$PID_FILE")" "$(dirname "$LOG_FILE")"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$SERVICE_NAME] $*"; }

_is_running() { [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; }

# Issue #23 (config Phase 3.3): register-then-start self-check. The service
# refuses to start on a port missing from port-registry.yaml so an unregistered
# port fails at start instead of being caught later by CI check-ports.
# FUSION_SKIP_REGISTRY_CHECK=1 bypasses; a missing registry file warns and
# continues (standalone deploy outside the workspace).
_registry_check() {
    local port="${FUSION_IDENTITY_PORT:-$DEFAULT_PORT}"
    local registry="${FUSION_REGISTRY:-$HOME/fusion/architecture/port-registry.yaml}"
    if [ ! -f "$registry" ]; then
        _log "WARN: port-registry.yaml not found at $registry — registry self-check skipped"
        return 0
    fi
    if grep -A3 "^  ${SERVICE_NAME}:" "$registry" 2>/dev/null | grep -q "port: ${port}$"; then
        _log "registry self-check ok: port ${port} registered for ${SERVICE_NAME}"
        return 0
    fi
    if [ "${FUSION_SKIP_REGISTRY_CHECK:-}" = "1" ]; then
        _log "WARN: registry check bypassed (FUSION_SKIP_REGISTRY_CHECK=1) — port ${port} unverified"
        return 0
    fi
    _log "ERROR: port ${port} for ${SERVICE_NAME} not registered in $registry — refusing to start"
    return 1
}

start() {
    if _is_running; then
        _log "already running (pid $(cat "$PID_FILE"))"
        return 0
    fi
    _log "starting on ${FUSION_IDENTITY_HOST:-$DEFAULT_HOST}:${FUSION_IDENTITY_PORT:-$DEFAULT_PORT}"
    _registry_check || return 1
    # shellcheck disable=SC1090
    source "$VENV_DIR/bin/activate" 2>/dev/null || true
    nohup fusion-identity >>"$LOG_FILE" 2>&1 &
    echo $! >"$PID_FILE"
    sleep 1
    if _is_running; then
        _log "started (pid $(cat "$PID_FILE"))"
        # Issue #64: persist required env for clean-shell restarts. 0600 —
        # signing keys and service token must not be world-readable.
        {
            for var in FUSION_IDENTITY_JWT_KEY FUSION_IDENTITY_SERVICE_TOKEN \
                FUSION_IDENTITY_KEK FUSION_IDENTITY_JWT_KEY_PREV \
                FUSION_IDENTITY_KEK_PREV FUSION_IDENTITY_DATABASE_URL \
                FUSION_IDENTITY_REDIS_URL FUSION_IDENTITY_GRPC_PORT \
                FUSION_IDENTITY_HOST FUSION_IDENTITY_PORT; do
                if [ -n "${!var:-}" ]; then
                    printf '%s=%q\n' "$var" "${!var}"
                fi
            done
        } >"$ENV_FILE"
        chmod 600 "$ENV_FILE"
    else
        _log "FAILED to start — see $LOG_FILE"
        tail -n 20 "$LOG_FILE" >&2 || true
        return 1
    fi
}

stop() {
    if ! _is_running; then
        _log "not running"
        rm -f "$PID_FILE"
        return 0
    fi
    local pid; pid="$(cat "$PID_FILE")"
    _log "stopping pid $pid"
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
        _log "graceful stop timed out, sending SIGKILL"
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    _log "stopped"
}

status() {
    if _is_running; then
        _log "running (pid $(cat "$PID_FILE"))"
        curl -fsS "http://${FUSION_IDENTITY_HOST:-$DEFAULT_HOST}:${FUSION_IDENTITY_PORT:-$DEFAULT_PORT}/health" 2>/dev/null && echo
    else
        _log "not running"
        return 1
    fi
}

log() {
    if [ "${1:-}" = "-f" ]; then
        tail -f "$LOG_FILE"
    else
        tail -n "${2:-100}" "$LOG_FILE"
    fi
}

compose() {
    local compose_file
    compose_file="$(cd "$(dirname "$0")" && pwd)/deploy/docker-compose.yml"
    case "${2:-up}" in
        up)
            _log "compose up (redis + identity)"
            docker compose -f "$compose_file" up -d --build
            ;;
        down)
            _log "compose down"
            docker compose -f "$compose_file" down
            ;;
        logs)
            docker compose -f "$compose_file" logs -f
            ;;
        *)
            echo "Usage: $0 compose {up|down|logs}" >&2
            exit 64
            ;;
    esac
}

case "${1:-status}" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    status) status ;;
    log) log "${2:-}" "${3:-}" ;;
    registry-check) _registry_check ;;
    compose) compose "$@" ;;
    *) echo "Usage: $0 {start|stop|restart|status|log [-f]|registry-check|compose {up|down|logs}}" >&2; exit 64 ;;
esac
