from __future__ import annotations

import asyncio
import logging
import smtplib
from email.message import EmailMessage
from typing import Any

logger = logging.getLogger(__name__)


class EmailDeliveryError(RuntimeError):
    pass


_VERIFY_BODY = (
    "Welcome to Fusion, {username}.\n\n"
    "Verify your email address by visiting:\n\n"
    "{base}/auth/?verify={token}\n\n"
    "This link is single-use and expires in {ttl_hours} hours.\n"
    "If you did not sign up, ignore this message.\n"
)

_RESET_BODY = (
    "Hi {username},\n\n"
    "A password reset was requested for your Fusion account. Set a new "
    "password by visiting:\n\n"
    "{base}/auth/reset?token={token}\n\n"
    "This link is single-use and expires in {ttl_minutes} minutes.\n"
    "If you did not request a reset, ignore this message — your password "
    "is unchanged.\n"
)


def _public_base(settings: Any) -> str:
    # Issue #51: shared base-URL contract for all emailed links. Empty →
    # relative link + loud warning; delivery is never refused.
    base = (getattr(settings, "public_base_url", "") or "").rstrip("/")
    if not base:
        logger.warning(
            "email_sender: FUSION_IDENTITY_PUBLIC_BASE_URL unset — emailed links "
            "will be relative and unresolvable; set it to the auth portal origin "
            "(e.g. https://fusion-mlx.cn)"
        )
    return base


def _send_sync(settings: Any, to_email: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or "fusion-identity@localhost"
    msg["To"] = to_email
    msg.set_content(body)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
        if settings.smtp_starttls:
            smtp.starttls()
        if settings.smtp_username:
            smtp.login(settings.smtp_username, settings.smtp_password)
        smtp.send_message(msg)


async def send_email(settings: Any, to_email: str, subject: str, body: str) -> str:
    # Issue #39: SMTP delivery off the event loop. When no SMTP host is
    # configured the message is LOGGED instead (dev fallback) — verification
    # still blocks login until completed, so the operator copies the link from
    # the log. Returns "sent" | "logged" so the caller can audit honestly.
    if not settings.smtp_host:
        link = next((ln for ln in body.splitlines() if "verify=" in ln or "reset=" in ln), body)
        logger.warning(
            "email_sender: SMTP not configured — verification message for %s logged "
            "instead of sent (dev fallback): %s",
            to_email,
            link,
        )
        return "logged"
    try:
        await asyncio.to_thread(_send_sync, settings, to_email, subject, body)
    except (smtplib.SMTPException, OSError) as exc:
        logger.error("email_sender: delivery to %s failed: %s", to_email, exc)
        raise EmailDeliveryError(f"email delivery failed: {exc}") from exc
    logger.info("email_sender: sent subject=%r to=%s", subject, to_email)
    return "sent"


async def send_verification_email(settings: Any, to_email: str, token: str, username: str) -> str:
    # Issue #39: the verification link body. The raw token travels ONLY in the
    # email (never in an API response — that would defeat the proof).
    # Issue #51: link matches the auth-portal contract {base}/auth/?verify={token}
    # (route owned by fusion-gateway web/auth/app.js). base comes from
    # FUSION_IDENTITY_PUBLIC_BASE_URL; when unset the link stays relative and
    # a loud warning tells the operator — delivery is never refused.
    base = _public_base(settings)
    body = _VERIFY_BODY.format(
        username=username,
        base=base,
        token=token,
        ttl_hours=max(1, settings.email_verify_ttl_seconds // 3600),
    )
    return await send_email(settings, to_email, "Verify your Fusion account", body)


async def send_password_reset_email(settings: Any, to_email: str, token: str, username: str) -> str:
    # Issue #54: the password reset link body. The raw token travels ONLY in
    # the email (never in an API response). Same base-URL contract as the
    # verification link (issue #51).
    base = _public_base(settings)
    body = _RESET_BODY.format(
        username=username,
        base=base,
        token=token,
        ttl_minutes=max(1, settings.password_reset_ttl_seconds // 60),
    )
    return await send_email(settings, to_email, "Reset your Fusion password", body)
