from __future__ import annotations

import logging

import pytest
from starlette.testclient import TestClient

from fusion_identity.store import InMemoryStore

logger = logging.getLogger(__name__)

# Issue #109: /api/messaging conversation threads. Wire contract frozen by
# fusion-web-shell apps/shell/src/lib/messaging.ts parsers.


def _add_member(client: TestClient, admin_token: str, username: str) -> str:
    resp = client.post(
        "/api/v1/tenants/default/members",
        json={"username": username, "password": "Password123", "role": "member"},
        headers={"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["user_id"]


def _login(client: TestClient, username: str, password: str = "Password123") -> str:
    resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password, "tenant_id": "default"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def test_messaging_requires_bearer(client: TestClient):
    resp = client.get("/api/messaging/conversations")
    assert resp.status_code == 401


def test_open_and_list_conversation_member_scoped(
    client: TestClient, admin_token: str, store: InMemoryStore
):
    _add_member(client, admin_token, "cust1")
    _add_member(client, admin_token, "cust2")
    tok1 = _login(client, "cust1")
    tok2 = _login(client, "cust2")

    # Shell sends NO X-Tenant-Id — tenant comes from the bearer claim via the
    # ASGI context middleware (issue #109 decision).
    opened = client.post(
        "/api/messaging/conversations",
        json={"scope": "factory_order", "ref": "ORD-7", "subject": "door squeaks"},
        headers={"Authorization": f"Bearer {tok1}"},
    )
    assert opened.status_code == 201, opened.text
    conv = opened.json()
    assert conv["id"].startswith("conv-")
    assert conv["scope"] == "factory_order"
    assert conv["ref"] == "ORD-7"
    assert conv["subject"] == "door squeaks"
    assert conv["status"] == "open"
    assert conv["linked_issue_id"] == ""
    assert isinstance(conv["updated_at"], float) and conv["updated_at"] > 0
    assert conv["unread"] == 0

    # Creator sees it.
    mine = client.get("/api/messaging/conversations", headers={"Authorization": f"Bearer {tok1}"})
    assert mine.status_code == 200
    ids = [c["id"] for c in mine.json()["conversations"]]
    assert conv["id"] in ids

    # Other member does NOT see it (per-user boundary inside the tenant).
    theirs = client.get("/api/messaging/conversations", headers={"Authorization": f"Bearer {tok2}"})
    assert [c["id"] for c in theirs.json()["conversations"]] == []

    # Operator (admin) sees ALL tenant threads.
    ops = client.get(
        "/api/messaging/conversations",
        headers={"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"},
    )
    assert conv["id"] in [c["id"] for c in ops.json()["conversations"]]


def test_thread_messages_roles_after_and_unread(
    client: TestClient, admin_token: str, store: InMemoryStore
):
    _add_member(client, admin_token, "cust3")
    tok = _login(client, "cust3")
    conv = client.post(
        "/api/messaging/conversations",
        json={"scope": "factory_order", "ref": "ORD-9", "subject": "help"},
        headers={"Authorization": f"Bearer {tok}"},
    ).json()
    cid = conv["id"]

    # Customer reply → sender_role customer, sender = username.
    posted = client.post(
        f"/api/messaging/conversations/{cid}/messages",
        json={"content": "still broken"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert posted.status_code == 201, posted.text
    msg = posted.json()
    assert msg["sender"] == "cust3"
    assert msg["sender_role"] == "customer"
    assert msg["conversation_id"] == cid
    assert isinstance(msg["ts"], float) and msg["ts"] > 0

    # Operator reply → sender_role operator. Admin has X-Tenant-Id matching.
    op_msg = client.post(
        f"/api/messaging/conversations/{cid}/messages",
        json={"content": "on it"},
        headers={"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"},
    )
    assert op_msg.status_code == 201
    assert op_msg.json()["sender_role"] == "operator"

    # unread: operator list shows the customer's message as unread (sender !=
    # viewer username); member GET messages marks read → unread clears.
    ops_list = client.get(
        "/api/messaging/conversations",
        headers={"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"},
    ).json()["conversations"]
    row = next(c for c in ops_list if c["id"] == cid)
    assert row["unread"] == 1

    got = client.get(
        f"/api/messaging/conversations/{cid}/messages",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert got.status_code == 200
    msgs = got.json()["messages"]
    assert [m["content"] for m in msgs] == ["still broken", "on it"]

    member_list = client.get(
        "/api/messaging/conversations", headers={"Authorization": f"Bearer {tok}"}
    ).json()["conversations"]
    assert next(c for c in member_list if c["id"] == cid)["unread"] == 0

    # after= filter: numeric id > after. First message id < second's.
    after_first = client.get(
        f"/api/messaging/conversations/{cid}/messages?after={msgs[0]['id']}",
        headers={"Authorization": f"Bearer {tok}"},
    ).json()["messages"]
    assert [m["id"] for m in after_first] == [msgs[1]["id"]]

    # Non-numeric after degrades to 0 (full thread), not a 500.
    bad = client.get(
        f"/api/messaging/conversations/{cid}/messages?after=abc",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert bad.status_code == 200
    assert len(bad.json()["messages"]) == 2


def test_cross_user_thread_access_blocked(client: TestClient, admin_token: str):
    _add_member(client, admin_token, "cust4")
    _add_member(client, admin_token, "cust5")
    tok4 = _login(client, "cust4")
    tok5 = _login(client, "cust5")
    conv = client.post(
        "/api/messaging/conversations",
        json={"scope": "factory_order", "ref": "ORD-11", "subject": "s"},
        headers={"Authorization": f"Bearer {tok4}"},
    ).json()
    cid = conv["id"]

    read = client.get(
        f"/api/messaging/conversations/{cid}/messages",
        headers={"Authorization": f"Bearer {tok5}"},
    )
    assert read.status_code == 403
    post = client.post(
        f"/api/messaging/conversations/{cid}/messages",
        json={"content": "intrude"},
        headers={"Authorization": f"Bearer {tok5}"},
    )
    assert post.status_code == 403


def test_patch_status_operator_only_verbatim(
    client: TestClient, admin_token: str, store: InMemoryStore
):
    _add_member(client, admin_token, "cust6")
    tok = _login(client, "cust6")
    conv = client.post(
        "/api/messaging/conversations",
        json={"scope": "factory_order", "ref": "ORD-12", "subject": "s"},
        headers={"Authorization": f"Bearer {tok}"},
    ).json()
    cid = conv["id"]

    # Member cannot set the status chip.
    denied = client.patch(
        f"/api/messaging/conversations/{cid}",
        json={"status": "closed"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert denied.status_code == 403

    # Operator sets a hyphenated chip; stored VERBATIM (client degrades
    # unknown values to 'open').
    patched = client.patch(
        f"/api/messaging/conversations/{cid}",
        json={"status": "in-progress", "linked_issue_id": "fusion-site#143"},
        headers={"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"},
    )
    assert patched.status_code == 200, patched.text
    body = patched.json()
    assert body["status"] == "in-progress"
    assert body["linked_issue_id"] == "fusion-site#143"

    listed = client.get(
        "/api/messaging/conversations", headers={"Authorization": f"Bearer {tok}"}
    ).json()["conversations"]
    row = next(c for c in listed if c["id"] == cid)
    assert row["status"] == "in-progress"

    missing = client.patch(
        "/api/messaging/conversations/conv-nope",
        json={"status": "closed"},
        headers={"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"},
    )
    assert missing.status_code == 404


def test_unknown_conversation_404(client: TestClient, admin_token: str):
    headers = {"Authorization": f"Bearer {admin_token}", "X-Tenant-Id": "default"}
    assert (
        client.get("/api/messaging/conversations/conv-nope/messages", headers=headers).status_code
        == 404
    )
    assert (
        client.post(
            "/api/messaging/conversations/conv-nope/messages",
            json={"content": "x"},
            headers=headers,
        ).status_code
        == 404
    )


def test_middleware_no_token_no_injection(app, store: InMemoryStore):
    # No bearer → no x-tenant-id injected → tenant middleware 401 (fail-closed).
    with TestClient(app) as c:
        assert c.get("/api/messaging/conversations").status_code == 401


@pytest.mark.asyncio
async def test_inmemory_store_messaging_basics(store: InMemoryStore):
    await store.create_user("u1", "u1", "pw")
    conv = await store.create_conversation("t1", "conv-a", "factory_order", "R1", "subj", "u1")
    assert conv["status"] == "open"
    assert await store.get_conversation("t1", "conv-a") is not None
    assert await store.get_conversation("t2", "conv-a") is None

    m1 = await store.append_message("t1", "conv-a", "u1", "customer", "hello")
    m2 = await store.append_message("t1", "conv-a", "op", "operator", "hi")
    assert m2["id"] == m1["id"] + 1

    rows = await store.list_conversations("t1", viewer_id="op", viewer_username="op")
    assert rows[0]["unread"] == 1  # u1's message unread for op (sender != op)
    await store.mark_conversation_read("t1", "conv-a", "op", m2["id"])
    rows = await store.list_conversations("t1", viewer_id="op", viewer_username="op")
    assert rows[0]["unread"] == 0
    rows_u1 = await store.list_conversations("t1", viewer_id="u1", viewer_username="u1")
    assert rows_u1[0]["unread"] == 1  # op's message unread for u1

    assert len(await store.list_messages("t1", "conv-a")) == 2
    assert len(await store.list_messages("t1", "conv-a", after_id=m1["id"])) == 1

    assert await store.set_conversation("t1", "conv-a", status="fixed") is True
    assert await store.set_conversation("t2", "conv-a", status="fixed") is False
    conv2 = await store.get_conversation("t1", "conv-a")
    assert conv2["status"] == "fixed"

    await store.mark_conversation_read("t1", "conv-a", "u1", m2["id"])
    rows_u1 = await store.list_conversations("t1", viewer_id="u1", viewer_username="u1")
    assert rows_u1[0]["unread"] == 0
