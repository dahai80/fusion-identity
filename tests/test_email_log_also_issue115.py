from __future__ import annotations

import logging
import smtplib
from types import SimpleNamespace

import pytest

import fusion_identity.email_sender as es
from fusion_identity.email_sender import EmailDeliveryError, send_email

logger = logging.getLogger(__name__)

BODY = "Welcome.\n\nVerify your email address by visiting:\n\n/auth/?verify=TOKEN115\n"

SENT: list[tuple[str, str]] = []


def _settings(env_name: str = "", smtp_host: str = "relay.example.com"):
    # Issue #115: minimal settings stub — send_email only touches the SMTP
    # fields + env_name; _send_sync is stubbed so no real relay is contacted.
    return SimpleNamespace(
        smtp_host=smtp_host,
        smtp_port=587,
        smtp_starttls=False,
        smtp_username="",
        smtp_password="",
        smtp_from="fusion-identity@test",
        env_name=env_name,
    )


@pytest.fixture(autouse=True)
def _stub_relay(monkeypatch):
    SENT.clear()
    monkeypatch.setattr(es, "_send_sync", lambda s, to, sub, body: SENT.append((to, sub)))


async def test_dev_smtp_success_logs_link_also(caplog):
    # Issue #115: SMTP configured + dev (FUSION_IDENTITY_ENV empty) — the
    # verification link must ALSO hit the log even though delivery succeeds.
    with caplog.at_level(logging.WARNING, logger="fusion_identity.email_sender"):
        result = await send_email(_settings(), "user@example.com", "Verify", BODY)
    assert result == "sent"
    assert SENT == [("user@example.com", "Verify")]
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("dev log-also" in m and "verify=TOKEN115" in m for m in warnings)


async def test_prod_smtp_success_send_only(caplog):
    # Issue #115: prod keeps send-only — no link ever lands in a log line.
    with caplog.at_level(logging.WARNING, logger="fusion_identity.email_sender"):
        result = await send_email(
            _settings(env_name="production"), "user@real.example", "Verify", BODY
        )
    assert result == "sent"
    assert not any("verify=TOKEN115" in r.message for r in caplog.records)


async def test_dev_smtp_failure_still_records_link(caplog, monkeypatch):
    # Issue #115 acceptance: SMTP send fails in dev — the code path must still
    # record the verification code (link) in the log so the token is not lost.
    def _boom(settings, to_email, subject, body):
        raise smtplib.SMTPException("relay down")

    monkeypatch.setattr(es, "_send_sync", _boom)
    with (
        caplog.at_level(logging.WARNING, logger="fusion_identity.email_sender"),
        pytest.raises(EmailDeliveryError),
    ):
        await send_email(_settings(), "user@example.com", "Verify", BODY)
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("delivery failed" in m and "verify=TOKEN115" in m for m in warnings)


async def test_test_domain_gets_undeliverable_warning(caplog):
    # Issue #115: reserved test domains cannot receive mail — the operator
    # must get a signal instead of silent loss.
    with caplog.at_level(logging.WARNING, logger="fusion_identity.email_sender"):
        await send_email(_settings(), "e2e@test.local", "Verify", BODY)
    warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("cannot receive mail" in m and "test.local" in m for m in warnings)


async def test_real_domain_no_undeliverable_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="fusion_identity.email_sender"):
        await send_email(_settings(env_name="production"), "ops@fusion-mlx.cn", "Verify", BODY)
    assert not any("cannot receive mail" in r.message for r in caplog.records)
