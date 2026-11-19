from __future__ import annotations

import logging

import pytest

from fusion_identity.config import ConfigError, load_settings

logger = logging.getLogger(__name__)


def test_health_reports_email_mode_logged(client):
    # Issue #103: default (no SMTP) — /health must expose the logged dev
    # fallback so monitoring can alert on it.
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["service"] == "fusion-identity"
    assert body["version"]
    assert body["email"] == "logged"


def test_health_reports_email_mode_smtp(app, client):
    import dataclasses

    from starlette.testclient import TestClient

    app.state.settings = dataclasses.replace(app.state.settings, smtp_host="smtp.example.com")
    with TestClient(app) as c:
        r = c.get("/health")
    assert r.json()["email"] == "smtp"


def test_email_mode_helper():
    from fusion_identity.email_sender import email_mode

    class S:
        smtp_host = ""

    assert email_mode(S()) == "logged"
    S.smtp_host = "relay.example.com"
    assert email_mode(S()) == "smtp"


def _base_env(monkeypatch):
    monkeypatch.setenv("FUSION_IDENTITY_JWT_KEY", "test-signing-key-please-not-prod-32bytes!")
    monkeypatch.setenv("FUSION_IDENTITY_SERVICE_TOKEN", "test-service-token-24bytes!!")
    monkeypatch.setenv("FUSION_IDENTITY_KEK", "test-kek-material-distinct-from-jwt-key")
    for var in (
        "FUSION_IDENTITY_DATABASE_URL",
        "FUSION_IDENTITY_REDIS_URL",
        "FUSION_IDENTITY_GRPC_PORT",
        "FUSION_IDENTITY_BOOTSTRAP_TENANTS",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.delenv("FUSION_IDENTITY_SMTP_HOST", raising=False)
    monkeypatch.delenv("FUSION_IDENTITY_ENV", raising=False)


def test_production_without_smtp_refuses_start(monkeypatch):
    # Issue #103 acceptance: prod with SMTP unset fails loudly — not 201+silent.
    _base_env(monkeypatch)
    monkeypatch.setenv("FUSION_IDENTITY_ENV", "production")
    with pytest.raises(ConfigError) as exc:
        load_settings()
    assert "FUSION_IDENTITY_SMTP_HOST" in str(exc.value)


def test_production_with_smtp_starts(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.setenv("FUSION_IDENTITY_ENV", "production")
    monkeypatch.setenv("FUSION_IDENTITY_SMTP_HOST", "relay.example.com")
    s = load_settings()
    assert s.env_name == "production"
    assert s.smtp_host == "relay.example.com"


def test_development_defaults_keep_logged_fallback(monkeypatch):
    _base_env(monkeypatch)
    s = load_settings()
    assert s.env_name == ""
    assert s.smtp_host == ""
