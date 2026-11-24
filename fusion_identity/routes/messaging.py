from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from fusion_identity.deps import get_store, require_bearer

logger = logging.getLogger(__name__)

# Issue #109: tenant-scoped conversation threads for the factory ticket flow
# (unblocks fusion-web-shell#186). Wire contract is frozen by the shell-side
# parsers (fusion-web-shell#187, apps/shell/src/lib/messaging.ts) — snake_case
# fields, epoch-float timestamps, hyphenated status chips. If the contract
# must change, change the parsers and this router in the same PR.

router = APIRouter(prefix="/api/messaging", tags=["messaging"])

OPERATOR_ROLES = frozenset({"tenant_admin", "operator"})

MAX_CONTENT = 8000
MAX_SUBJECT = 500
MAX_REF = 200
MAX_SCOPE = 100
MAX_STATUS = 64


def _is_operator(claims: dict[str, Any]) -> bool:
    return claims.get("role") in OPERATOR_ROLES


def _sender_role(claims: dict[str, Any]) -> str:
    # 'system' is reserved for server-generated notices; service-role callers
    # act on behalf of the platform.
    if claims.get("role") == "service":
        return "system"
    return "operator" if _is_operator(claims) else "customer"


def _conv_wire(conv: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": conv["id"],
        "scope": conv.get("scope", ""),
        "ref": conv.get("ref", ""),
        "subject": conv.get("subject", ""),
        "status": conv.get("status", "open"),
        "linked_issue_id": conv.get("linked_issue_id", ""),
        "updated_at": float(conv.get("updated_at") or 0.0),
        "unread": int(conv.get("unread") or 0),
    }


def _msg_wire(msg: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(msg["id"]),
        "conversation_id": msg["conversation_id"],
        "sender": msg.get("sender", ""),
        "sender_role": msg.get("sender_role", "operator"),
        "content": msg.get("content", ""),
        "ts": float(msg.get("created_at") or 0.0),
    }


class ConversationOpen(BaseModel):
    scope: str = Field(default="factory_order", max_length=MAX_SCOPE)
    ref: str = Field(default="", max_length=MAX_REF)
    subject: str = Field(max_length=MAX_SUBJECT)


class MessagePost(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_CONTENT)


class ConversationPatch(BaseModel):
    status: str | None = Field(default=None, max_length=MAX_STATUS)
    linked_issue_id: str | None = Field(default=None, max_length=MAX_REF)


@router.get("/conversations")
async def list_conversations(
    claims: dict = Depends(require_bearer),
    store: Any = Depends(get_store),
) -> dict[str, Any]:
    # Operator roles see every thread in their tenant; everyone else sees
    # only the threads they opened (customer side).
    tid = claims["tid"]
    username = await _username(store, claims)
    rows = await store.list_conversations(
        tid,
        created_by=None if _is_operator(claims) else claims["sub"],
        viewer_id=claims["sub"],
        viewer_username=username,
    )
    return {"conversations": [_conv_wire(c) for c in rows]}


@router.post("/conversations", status_code=201)
async def open_conversation(
    req: ConversationOpen,
    claims: dict = Depends(require_bearer),
    store: Any = Depends(get_store),
) -> dict[str, Any]:
    conv_id = "conv-" + uuid.uuid4().hex[:12]
    conv = await store.create_conversation(
        claims["tid"], conv_id, req.scope, req.ref, req.subject, claims["sub"]
    )
    try:
        await store.append_audit(
            tenant_id=claims["tid"],
            user_id=claims["sub"],
            jti=None,
            role=claims.get("role", "member"),
            action="messaging.conversation_opened",
            resource=conv_id,
            detail={"scope": req.scope, "ref": req.ref},
        )
    except Exception:
        logger.exception("open_conversation: audit append failed conv=%s", conv_id)
    logger.info(
        "open_conversation: tenant=%s conv=%s by=%s scope=%s ref=%s",
        claims["tid"],
        conv_id,
        claims["sub"],
        req.scope,
        req.ref,
    )
    return _conv_wire(conv)


async def _visible_conversation(
    store: Any, claims: dict[str, Any], conversation_id: str
) -> dict[str, Any]:
    conv = await store.get_conversation(claims["tid"], conversation_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="conversation not found")
    if not _is_operator(claims) and conv["created_by"] != claims["sub"]:
        # Cross-user thread read blocked at the tenant boundary (red line #2
        # is tenant-level; this adds the per-user boundary inside the tenant).
        logger.warning(
            "messaging: cross-user thread access blocked conv=%s by=%s",
            conversation_id,
            claims["sub"],
        )
        raise HTTPException(status_code=403, detail="not your conversation")
    return conv


@router.get("/conversations/{conversation_id}/messages")
async def list_messages(
    conversation_id: str,
    after: str = Query(default=""),
    claims: dict = Depends(require_bearer),
    store: Any = Depends(get_store),
) -> dict[str, Any]:
    conv = await _visible_conversation(store, claims, conversation_id)
    try:
        after_id = int(after) if after else 0
    except ValueError:
        after_id = 0
    rows = await store.list_messages(claims["tid"], conversation_id, after_id=after_id)
    # Thread read = read marker advances to the newest message in the thread
    # (not just the last page) so the unread chip clears.
    msgs = await store.list_messages(claims["tid"], conversation_id)
    if msgs:
        await store.mark_conversation_read(
            claims["tid"], conversation_id, claims["sub"], int(msgs[-1]["id"])
        )
    logger.info(
        "list_messages: tenant=%s conv=%s after=%s count=%d",
        claims["tid"],
        conversation_id,
        after or "0",
        len(rows),
    )
    del conv
    return {"messages": [_msg_wire(m) for m in rows]}


@router.post("/conversations/{conversation_id}/messages", status_code=201)
async def post_message(
    conversation_id: str,
    req: MessagePost,
    claims: dict = Depends(require_bearer),
    store: Any = Depends(get_store),
) -> dict[str, Any]:
    await _visible_conversation(store, claims, conversation_id)
    username = await _username(store, claims)
    msg = await store.append_message(
        claims["tid"], conversation_id, username, _sender_role(claims), req.content
    )
    if msg is None:
        raise HTTPException(status_code=404, detail="conversation not found")
    logger.info(
        "post_message: tenant=%s conv=%s by=%s role=%s len=%d",
        claims["tid"],
        conversation_id,
        claims["sub"],
        msg["sender_role"],
        len(req.content),
    )
    return _msg_wire(msg)


@router.patch("/conversations/{conversation_id}")
async def patch_conversation(
    conversation_id: str,
    req: ConversationPatch,
    claims: dict = Depends(require_bearer),
    store: Any = Depends(get_store),
) -> dict[str, Any]:
    if not _is_operator(claims):
        raise HTTPException(status_code=403, detail="operator role required")
    # Status chips are stored VERBATIM — the shell degrades unknown values to
    # 'open' client-side (issue #109 wire contract). linked_issue_id links the
    # mirrored GitHub issue (fusion-site#143 flow).
    ok = await store.set_conversation(
        claims["tid"], conversation_id, status=req.status, linked_issue_id=req.linked_issue_id
    )
    if not ok:
        raise HTTPException(status_code=404, detail="conversation not found")
    try:
        await store.append_audit(
            tenant_id=claims["tid"],
            user_id=claims["sub"],
            jti=None,
            role=claims.get("role", "operator"),
            action="messaging.conversation_updated",
            resource=conversation_id,
            detail={"status": req.status, "linked_issue_id": req.linked_issue_id},
        )
    except Exception:
        logger.exception("patch_conversation: audit append failed conv=%s", conversation_id)
    conv = await store.get_conversation(claims["tid"], conversation_id)
    return _conv_wire(conv)


async def _username(store: Any, claims: dict[str, Any]) -> str:
    u = await store.get_user(claims["sub"])
    return (u or {}).get("username") or claims["sub"]
