from __future__ import annotations

import logging

import pytest
from starlette.testclient import TestClient

from fusion_identity.app import build_app
from fusion_identity.store import InMemoryStore, StoreConflict
from tests.conftest import _settings

logger = logging.getLogger(__name__)


@pytest.fixture
def client() -> TestClient:
    app = build_app(_settings(), store=InMemoryStore(), run_bootstrap=True)
    with TestClient(app) as c:
        yield c


def _register(client: TestClient, username: str, email: str):
    return client.post(
        "/api/v1/auth/register",
        json={"username": username, "password": "S3curePass!2026x", "email": email},
    )


def test_duplicate_email_conflict(client):
    r1 = _register(client, "alice", "alice@example.com")
    assert r1.status_code == 201
    r2 = _register(client, "alice2", "alice@example.com")
    assert r2.status_code == 409
    assert r2.json()["detail"] == "email already registered"
    logger.info("duplicate email 409 verified")


def test_duplicate_email_case_insensitive(client):
    r1 = _register(client, "bob", "bob@Example.com")
    assert r1.status_code == 201
    r2 = _register(client, "bob2", "BOB@example.com")
    assert r2.status_code == 409
    assert r2.json()["detail"] == "email already registered"


def test_duplicate_username_still_conflicts(client):
    r1 = _register(client, "carol", "carol@example.com")
    assert r1.status_code == 201
    r2 = _register(client, "carol", "other@example.com")
    assert r2.status_code == 409
    assert r2.json()["detail"] == "username already exists"


def test_register_tenant_duplicate_admin_email(client):
    r1 = _register(client, "dave", "dave@example.com")
    assert r1.status_code == 201
    r2 = client.post(
        "/api/v1/auth/register-tenant",
        json={
            "tenant_display_name": "Acme",
            "admin_username": "daveadmin",
            "admin_password": "S3cureAdminPass!2026",
            "admin_email": "dave@example.com",
        },
    )
    assert r2.status_code == 409
    assert r2.json()["detail"] == "email already registered"


async def test_create_race_falls_back_to_conflict(client, monkeypatch):
    # Issue #53: two concurrent signups race past the pre-checks; the store's
    # unique constraint raises StoreConflict and the route must still 409.
    async def _no_email(self, email):
        return None

    async def _race(self, *args, **kwargs):
        raise StoreConflict("usr_race exists")

    from fusion_identity.store import InMemoryStore as S

    monkeypatch.setattr(S, "get_user_by_email", _no_email)
    monkeypatch.setattr(S, "create_user", _race)
    r = _register(client, "eve", "eve@example.com")
    assert r.status_code == 409
    assert r.json()["detail"] == "username or email already registered"
