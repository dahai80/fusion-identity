from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

logger = logging.getLogger(__name__)

KNOWN_PROVIDERS = ("stub",)


class PaymentError(RuntimeError):
    pass


@dataclass(frozen=True)
class PaymentResult:
    provider_ref: str
    provider: str


class PaymentProvider:
    # Issue #74: minimal provider seam. Currency conversion happens at the
    # payment layer; identity only ever sees tokens.
    name = "base"

    async def charge(self, tenant_id: str, order_id: str, tokens: int) -> PaymentResult:
        raise NotImplementedError

    async def refund(self, tenant_id: str, order_id: str, provider_ref: str) -> bool:
        raise NotImplementedError


class StubProvider(PaymentProvider):
    # Dev/test provider: confirms instantly. Never use with real money —
    # it exists so the recharge flow is exercisable end-to-end before a
    # real PSP integration lands.
    name = "stub"

    async def charge(self, tenant_id: str, order_id: str, tokens: int) -> PaymentResult:
        ref = "stub_" + secrets.token_hex(8)
        logger.info(
            "payment charge: provider=stub tenant=%s order=%s tokens=%d ref=%s",
            tenant_id,
            order_id,
            tokens,
            ref,
        )
        return PaymentResult(provider_ref=ref, provider=self.name)

    async def refund(self, tenant_id: str, order_id: str, provider_ref: str) -> bool:
        logger.info(
            "payment refund: provider=stub tenant=%s order=%s ref=%s",
            tenant_id,
            order_id,
            provider_ref,
        )
        return True


def get_provider(name: str) -> PaymentProvider:
    # Fail-closed: an unknown provider name is a config error, not a silent
    # fallback to stub (that would hand out paid tokens for free).
    if name == "stub":
        return StubProvider()
    logger.error("payments: unknown provider %r — refusing (fail-closed)", name)
    raise PaymentError(f"unknown payment provider: {name}")


def compute_promo(tokens: int, pct: int, first_paid_order: bool) -> int:
    # Promo applies ONCE per tenant — on the first paid order only.
    if pct <= 0 or not first_paid_order:
        return 0
    promo = tokens * pct // 100
    logger.info("payments: promo first_purchase pct=%d tokens=%d promo=%d", pct, tokens, promo)
    return promo
