from __future__ import annotations

import dataclasses
import logging

import pytest

from fusion_identity.email_sender import send_verification_email
from tests.conftest import _settings

logger = logging.getLogger(__name__)


@pytest.fixture
def base_settings():
    # SMTP set so the send path is exercised; send itself is monkeypatched.
    return dataclasses.replace(_settings(), smtp_host="smtp.example", smtp_from="no-reply@example")


async def test_link_absolute_with_public_base_url(base_settings, monkeypatch, caplog):
    s = dataclasses.replace(base_settings, public_base_url="https://fusion.example")
    captured: dict[str, str] = {}

    async def fake_send(settings, to_email, subject, body):
        captured["body"] = body
        return "sent"

    monkeypatch.setattr("fusion_identity.email_sender.send_email", fake_send)
    with caplog.at_level(logging.WARNING, logger="fusion_identity.email_sender"):
        out = await send_verification_email(s, "u@example", "tok123", "alice")
    assert out == "sent"
    assert "https://fusion.example/auth/?verify=tok123" in captured["body"]
    assert "/verify-email?token=" not in captured["body"]
    assert not any("PUBLIC_BASE_URL" in r.message for r in caplog.records)


async def test_link_relative_without_base_url_warns(base_settings, monkeypatch, caplog):
    captured: dict[str, str] = {}

    async def fake_send(settings, to_email, subject, body):
        captured["body"] = body
        return "sent"

    monkeypatch.setattr("fusion_identity.email_sender.send_email", fake_send)
    s = base_settings
    with caplog.at_level(logging.WARNING, logger="fusion_identity.email_sender"):
        out = await send_verification_email(s, "u@example", "tok456", "bob")
    assert out == "sent"
    assert "/auth/?verify=tok456" in captured["body"]
    assert any("FUSION_IDENTITY_PUBLIC_BASE_URL" in r.message for r in caplog.records)
    logger.info("relative-link warning verified")


async def test_base_url_trailing_slash_normalized(base_settings, monkeypatch):
    s = dataclasses.replace(base_settings, public_base_url="https://fusion.example/")
    captured: dict[str, str] = {}

    async def fake_send(settings, to_email, subject, body):
        captured["body"] = body
        return "sent"

    monkeypatch.setattr("fusion_identity.email_sender.send_email", fake_send)
    await send_verification_email(s, "u@example", "tok789", "carol")
    assert "https://fusion.example/auth/?verify=tok789" in captured["body"]


async def test_dev_fallback_logs_verify_link(monkeypatch, caplog):
    # SMTP unset: body logged via the dev fallback; the logged line must
    # contain the verify link (issue #51 renamed the query param).
    s = _settings()
    with caplog.at_level(logging.WARNING, logger="fusion_identity.email_sender"):
        out = await send_verification_email(s, "u@example", "tokdev", "dave")
    assert out == "logged"
    assert any("verify=tokdev" in r.message for r in caplog.records)
