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

if [ -z "${FUSION_IDENTITY_JWT_KEY:-}" ]; then
    echo "ERROR: FUSION_IDENTITY_JWT_KEY unset — service refuses to start (fail-closed)" >&2
    exit 2
fi
if [ -z "${FUSION_IDENTITY_SERVICE_TOKEN:-}" ]; then
    echo "ERROR: FUSION_IDENTITY_SERVICE_TOKEN unset — verify endpoint would be unprotected" >&2
    exit 2
fi

mkdir -p "$(dirname "$PID_FILE")" "$(dirname "$LOG_FILE")"

_log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$SERVICE_NAME] $*"; }

_is_running() { [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; }

start() {
    if _is_running; then
        _log "already running (pid $(cat "$PID_FILE"))"
        return 0
    fi
    _log "starting on ${FUSION_IDENTITY_HOST:-$DEFAULT_HOST}:${FUSION_IDENTITY_PORT:-$DEFAULT_PORT}"
    # shellcheck disable=SC1090
    source "$VENV_DIR/bin/activate" 2>/dev/null || true
    nohup fusion-identity >>"$LOG_FILE" 2>&1 &
    echo $! >"$PID_FILE"
    sleep 1
    if _is_running; then
        _log "started (pid $(cat "$PID_FILE"))"
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

case "${1:-status}" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    status) status ;;
    log) log "${2:-}" "${3:-}" ;;
    *) echo "Usage: $0 {start|stop|restart|status|log [-f]|}" >&2; exit 64 ;;
esac
