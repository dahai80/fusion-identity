from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)

DEFAULT_LOGIN_LIMIT = 10
DEFAULT_LOGIN_WINDOW = 60
# P1: hard cap on tracked buckets so a spoofed-IP flood cannot exhaust memory.
MAX_BUCKETS = 8192


@dataclass
class _Bucket:
    tokens: float
    last: float


@dataclass
class LoginRateLimiter:
    max_tokens: float
    window: float
    _buckets: dict[str, _Bucket] = field(default_factory=dict)

    def _key(self, tenant_id: str, ip: str, username: str | None = None) -> str:
        # P2-5: key on (tenant, ip) for the IP bucket AND a separate per-account
        # bucket so a botnet spreading guesses across IPs still hits a per-account
        # throttle. A single NAT hammering many accounts also hits the IP bucket.
        if username:
            return f"u:{tenant_id}:{username.lower()}"
        return f"{tenant_id}:{ip}"

    def allow(self, tenant_id: str, ip: str, username: str | None = None) -> bool:
        if self.max_tokens <= 0:
            return True
        now = time.time()
        refill = self.max_tokens / self.window
        # P2-5: check both the IP bucket and the per-username bucket; deny if
        # either is exhausted.
        keys = [self._key(tenant_id, ip)]
        if username:
            keys.append(self._key(tenant_id, ip, username))
        return all(self._consume(key, now, refill, tenant_id, ip, username) for key in keys)

    def _consume(
        self,
        key: str,
        now: float,
        refill: float,
        tenant_id: str,
        ip: str,
        username: str | None,
    ) -> bool:
        b = self._buckets.get(key)
        if b is None:
            # P1: evict stalest bucket when the cap is reached before inserting
            # a new one — bounded memory under XFF-spoof flood (paired with F8).
            if len(self._buckets) >= MAX_BUCKETS:
                self.sweep(now)
            if len(self._buckets) >= MAX_BUCKETS:
                oldest = min(self._buckets, key=lambda k: self._buckets[k].last)
                self._buckets.pop(oldest, None)
                logger.warning("login_ratelimit: bucket cap reached, evicted %s", oldest)
            b = _Bucket(tokens=self.max_tokens, last=now)
            self._buckets[key] = b
        elapsed = now - b.last
        b.tokens = min(self.max_tokens, b.tokens + elapsed * refill)
        b.last = now
        if b.tokens < 1.0:
            logger.warning(
                "login_ratelimit: deny tenant=%s ip=%s user=%s bucket=%s tokens=%.2f",
                tenant_id,
                ip,
                username,
                key.split(":", 1)[0],
                b.tokens,
            )
            return False
        b.tokens -= 1.0
        return True

    def sweep(self, now: float) -> int:
        stale = [k for k, b in self._buckets.items() if now - b.last > self.window * 2]
        for k in stale:
            self._buckets.pop(k, None)
        if stale:
            logger.info("login_ratelimit: swept %s stale buckets", len(stale))
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
    # F8: only honor X-Forwarded-For when the direct TCP peer is a configured
    # trusted proxy. Otherwise a client can spoof XFF to rotate buckets and
    # bypass login rate-limiting entirely.
    peer = request.client.host if request.client else "unknown"
    settings = getattr(request.app.state, "settings", None)
    trusted = getattr(settings, "trusted_proxies", frozenset()) or frozenset()
    if peer in trusted:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return peer


def check_login_rate(request: Request, tenant_id: str, username: str | None = None) -> None:
    limiter = get_login_limiter(request)
    ip = client_ip(request)
    if not limiter.allow(tenant_id, ip, username):
        logger.warning("login_ratelimit: 429 tenant=%s ip=%s user=%s", tenant_id, ip, username)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts, retry later",
        )
