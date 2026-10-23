from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Issue #14 (M-B): lifecycle event outbox + signed webhook delivery. Events are
# always appended to the outbox (pull via GET /api/v1/admin/events?cursor=);
# when FUSION_IDENTITY_WEBHOOK_URL + SECRET are set a background worker also
# pushes them (HMAC-SHA256 signed) with retry + dead-letter.

EVENT_TENANT_CREATED = "tenant.created"
EVENT_TENANT_QUOTA_CHANGED = "tenant.quota_changed"
EVENT_TENANT_STATUS_CHANGED = "tenant.status_changed"
EVENT_TENANT_DELETED = "tenant.deleted"
EVENT_APIKEY_CREATED = "apikey.created"
EVENT_APIKEY_REVOKED = "apikey.revoked"

WEBHOOK_TIMEOUT_SECONDS = 5.0
HOOK_TIMEOUT_SECONDS = 3.0


def sign_payload(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def emit_event(store: Any, event_type: str, tenant_id: str, payload: dict[str, Any]) -> None:
    # The event plane must never break the primary write path — a delivery
    # failure is logged loudly, not raised.
    try:
        await store.append_event(event_type, tenant_id, payload)
    except Exception as exc:
        logger.error("emit_event: %s tenant=%s FAILED: %s", event_type, tenant_id, exc)


async def dispatch_hook(url: str, secret: str, event: str, data: dict[str, Any]) -> dict[str, Any]:
    # Issue #14 (M-D): generic post-provision hook — POST the provision result
    # to a caller-supplied URL so the control plane can register downstream
    # keys (e.g. fusion-gateway) without polling. Best-effort, no
    # service-specific code in identity.
    import httpx

    body = {"event": event, "data": data}.encode()
    headers = {
        "Content-Type": "application/json",
        "X-Fusion-Event": event,
        "X-Fusion-Signature": f"sha256={sign_payload(secret, body)}",
    }
    try:
        async with httpx.AsyncClient(timeout=HOOK_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, content=body, headers=headers)
        ok = 200 <= resp.status_code < 300
        if not ok:
            logger.warning(
                "dispatch_hook: url=%s event=%s status=%d body=%s",
                url,
                event,
                resp.status_code,
                resp.text[:200],
            )
        return {"status": "delivered" if ok else "rejected", "http_status": resp.status_code}
    except Exception as exc:
        logger.warning("dispatch_hook: url=%s event=%s failed: %s", url, event, exc)
        return {"status": "failed", "error": str(exc)}


class WebhookWorker:
    # Background outbox drainer: every tick, deliver pending events to the
    # configured webhook endpoint; after max_attempts the event is marked dead
    # (dead-letter) and stays queryable in the outbox for reprocessing.

    def __init__(
        self,
        store: Any,
        url: str,
        secret: str,
        *,
        tick_seconds: float = 5.0,
        max_attempts: int = 5,
        batch_size: int = 20,
        http_client: Any = None,
    ) -> None:
        self._store = store
        self._url = url
        self._secret = secret
        self._tick_seconds = tick_seconds
        self._max_attempts = max_attempts
        self._batch_size = batch_size
        self._http_client = http_client
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def _deliver_one(self, client: Any, event: dict[str, Any]) -> None:
        import json as _json

        body = _json.dumps(
            {
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "tenant_id": event["tenant_id"],
                "payload": event["payload"],
                "created_at": event["created_at"],
            }
        ).encode()
        headers = {
            "Content-Type": "application/json",
            "X-Fusion-Event-Id": event["event_id"],
            "X-Fusion-Event": event["event_type"],
            "X-Fusion-Signature": f"sha256={sign_payload(self._secret, body)}",
        }
        attempts = int(event.get("attempts", 0)) + 1
        try:
            resp = await client.post(self._url, content=body, headers=headers)
            ok = 200 <= resp.status_code < 300
        except Exception as exc:
            logger.warning(
                "webhook: event=%s type=%s attempt=%d failed: %s",
                event["event_id"],
                event["event_type"],
                attempts,
                exc,
            )
            ok = False
        if ok:
            await self._store.mark_event(event["event_id"], "delivered", attempts)
            logger.info(
                "webhook: event=%s type=%s delivered (attempt=%d)",
                event["event_id"],
                event["event_type"],
                attempts,
            )
        elif attempts >= self._max_attempts:
            await self._store.mark_event(event["event_id"], "dead", attempts)
            logger.error(
                "webhook: event=%s type=%s DEAD after %d attempts (dead-lettered)",
                event["event_id"],
                event["event_type"],
                attempts,
            )
        else:
            await self._store.mark_event(event["event_id"], "pending", attempts)

    async def _tick(self) -> None:
        import httpx

        events = await self._store.pending_events(self._batch_size)
        if not events:
            return
        own_client = self._http_client is None
        client = self._http_client or httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT_SECONDS)
        try:
            for event in events:
                if self._stop.is_set():
                    break
                await self._deliver_one(client, event)
        finally:
            if own_client:
                await client.aclose()

    async def _run(self) -> None:
        logger.info("webhook worker: start url=%s tick=%ss", self._url, self._tick_seconds)
        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception as exc:
                logger.error("webhook worker: tick failed: %s", exc)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=self._tick_seconds)
        logger.info("webhook worker: stopped")

    def start(self) -> None:
        self._stop.clear()
        self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=10)
            except (TimeoutError, asyncio.CancelledError):
                self._task.cancel()
            self._task = None
