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


class ResetBackoff:
    # Issue #98: per-account + per-IP cooldown with exponential backoff for
    # the password-reset request plane. Keyed on the REQUESTED email and the
    # client IP BEFORE any account lookup — throttling is identical for
    # existing and non-existing accounts, so it leaks nothing. Each request
    # inside the quiet period doubles the delay; a spike threshold logs a
    # WARNING so operators can see hammering in the journal.
    SPIKE_THRESHOLD = 3
    MAX_KEYS = 8192
    QUIET_RESET_FACTOR = 4

    def __init__(self, base_seconds: float, cap_seconds: float) -> None:
        self.base = float(base_seconds)
        self.cap = float(cap_seconds)
        self._hits: dict[str, tuple[float, int]] = {}

    def hit(self, key: str, now: float | None = None) -> float:
        # Returns 0.0 when allowed; otherwise the seconds the caller must
        # wait (a strictly growing sequence under hammering).
        if self.base <= 0 or self.cap <= 0:
            return 0.0
        now = time.time() if now is None else now
        if len(self._hits) >= self.MAX_KEYS and key not in self._hits:
            self._sweep(now)
        last, count = self._hits.get(key, (0.0, 0))
        if now - last > self.base * self.QUIET_RESET_FACTOR:
            count = 0
        delay = min(self.base * (2**count), self.cap)
        self._hits[key] = (now, count + 1)
        if count >= self.SPIKE_THRESHOLD:
            logger.warning(
                "reset_backoff: spike key=%s attempts=%d next_delay=%.0fs", key, count + 1, delay
            )
        # Two free requests (burst tolerance) so a double-submit or a human
        # retrying after a typo is never throttled; the third rapid request
        # starts the exponential ladder.
        if count < 2:
            return 0.0
        logger.info("reset_backoff: throttle key=%s retry_after=%.0fs", key, delay)
        return delay

    def _sweep(self, now: float) -> None:
        stale = [k for k, (last, _) in self._hits.items() if now - last > self.cap * 2]
        for k in stale:
            self._hits.pop(k, None)
        if stale:
            logger.info("reset_backoff: swept %s stale keys", len(stale))


def get_reset_backoff(request: Request) -> ResetBackoff:
    backoff: ResetBackoff | None = getattr(request.app.state, "reset_backoff", None)
    if backoff is None:
        settings = getattr(request.app.state, "settings", None)
        backoff = ResetBackoff(
            base_seconds=getattr(settings, "reset_backoff_base_seconds", 2),
            cap_seconds=getattr(settings, "reset_backoff_cap_seconds", 300),
        )
        request.app.state.reset_backoff = backoff
    return backoff


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


async def check_login_rate(
    request: Request,
    tenant_id: str,
    username: str | None = None,
    *,
    limit: int | None = None,
    window: int | None = None,
) -> None:
    # Issue #69: optional limit/window override so non-login planes (e.g.
    # /refresh) get their own budget instead of inheriting the login one.
    ip = client_ip(request)
    cache = getattr(request.app.state, "cache", None)
    settings = getattr(request.app.state, "settings", None)
    if limit is None:
        limit = getattr(settings, "login_rate_limit", DEFAULT_LOGIN_LIMIT) or 0
    if window is None:
        window = (
            getattr(settings, "login_rate_window", DEFAULT_LOGIN_WINDOW) or DEFAULT_LOGIN_WINDOW
        )
    # P1-4: prefer the Redis-backed limiter when the cache plane is active so
    # the configured limit is enforced across workers (in-memory gives N×).
    # Fall back to the process-local limiter only when redis is absent.
    if cache is not None and limit > 0:
        try:
            allowed = await cache.check_login_rate(tenant_id, ip, username, limit, window)
        except Exception as exc:
            logger.warning("login_ratelimit: redis path failed, fallback in-memory: %s", exc)
            allowed = None
        if allowed is False:
            logger.warning(
                "login_ratelimit: 429 tenant=%s ip=%s user=%s (redis)", tenant_id, ip, username
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many login attempts, retry later",
            )
        if allowed is True:
            return
    limiter = get_login_limiter(request)
    if (limit, window) != (limiter.max_tokens, limiter.window):
        # Issue #69: override budget (e.g. the /refresh plane) — separate
        # limiter instance per (limit, window) so it does not share buckets
        # or the token budget with the login limiter.
        override: LoginRateLimiter | None = getattr(request.app.state, "rate_limiters", {}).get(
            (limit, window)
        )
        if override is None:
            override = LoginRateLimiter(max_tokens=limit, window=window)
            if not hasattr(request.app.state, "rate_limiters"):
                request.app.state.rate_limiters = {}
            request.app.state.rate_limiters[(limit, window)] = override
        limiter = override
    if not limiter.allow(tenant_id, ip, username):
        logger.warning("login_ratelimit: 429 tenant=%s ip=%s user=%s", tenant_id, ip, username)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts, retry later",
        )
