from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

DEFAULT_LOGIN_LIMIT = 10
DEFAULT_LOGIN_WINDOW = 60


@dataclass
class _Bucket:
    tokens: float
    last: float


@dataclass
class LoginRateLimiter:
    max_tokens: float
    window: float
    _buckets: dict[str, _Bucket] = field(default_factory=dict)

    def _key(self, tenant_id: str, ip: str) -> str:
        return f"{tenant_id}:{ip}"

    def allow(self, tenant_id: str, ip: str) -> bool:
        if self.max_tokens <= 0:
            return True
        key = self._key(tenant_id, ip)
        now = time.time()
        refill = self.max_tokens / self.window
        b = self._buckets.get(key)
        if b is None:
            b = _Bucket(tokens=self.max_tokens, last=now)
            self._buckets[key] = b
        elapsed = now - b.last
        b.tokens = min(self.max_tokens, b.tokens + elapsed * refill)
        b.last = now
        if b.tokens < 1.0:
            logger.warning(
                "login_ratelimit: deny tenant=%s ip=%s tokens=%.2f", tenant_id, ip, b.tokens
            )
            return False
        b.tokens -= 1.0
        return True

    def sweep(self, now: float) -> int:
        stale = [k for k, b in self._buckets.items() if now - b.last > self.window * 2]
        for k in stale:
            self._buckets.pop(k, None)
        return len(stale)


def get_login_limiter(request: Request) -> LoginRateLimiter:
    limiter: LoginRateLimiter | None = getattr(request.app.state, "login_limiter", None)
    if limiter is None:
        settings = getattr(request.app.state, "settings", None)
        max_tokens = getattr(settings, "login_rate_limit", DEFAULT_LOGIN_LIMIT) or 0
        window = (
            getattr(settings, "login_rate_window", DEFAULT_LOGIN_WINDOW) or DEFAULT_LOGIN_WINDOW
        )
        limiter = LoginRateLimiter(max_tokens=max_tokens, window=window)
        request.app.state.login_limiter = limiter
    return limiter


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_login_rate(request: Request, tenant_id: str) -> None:
    limiter = get_login_limiter(request)
    ip = client_ip(request)
    if not limiter.allow(tenant_id, ip):
        logger.warning("login_ratelimit: 429 tenant=%s ip=%s", tenant_id, ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts, retry later",
        )
