from __future__ import annotations

import logging
import secrets
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from fusion_identity.crypto import decrypt_secret
from fusion_identity.deps import get_settings
from fusion_identity.models import OidcCallbackRequest

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth/oidc", tags=["oidc"])

_STATES: OrderedDict[str, dict[str, Any]] = OrderedDict()
_STATES_MAX = 1024
_STATES_TTL = 600


def _purge_states() -> None:
    now = time.time()
    expired = [k for k, v in _STATES.items() if now - v.get("ts", 0) > _STATES_TTL]
    for k in expired:
        _STATES.pop(k, None)


def _put_state(state: str, info: dict[str, Any]) -> None:
    _purge_states()
    _STATES[state] = {**info, "ts": time.time()}
    _STATES.move_to_end(state)
    while len(_STATES) > _STATES_MAX:
        _STATES.popitem(last=False)


@router.get("/{idp_id}/login")
async def oidc_login(idp_id: str, request: Request) -> RedirectResponse:
    store = request.app.state.store
    idp = await store.get_idp(idp_id)
    if idp is None:
        raise HTTPException(status_code=404, detail="idp not found")
    if not idp.get("issuer_url"):
        raise HTTPException(status_code=400, detail="idp missing issuer_url")
    state = secrets.token_hex(8)
    _put_state(state, {"idp_id": idp_id, "tenant_id": idp["tenant_id"]})
    params = {
        "response_type": "code",
        "client_id": idp.get("client_id") or "",
        "redirect_uri": _redirect_uri(request, idp_id),
        "scope": idp.get("scopes") or "openid profile email",
        "state": state,
    }
    authorize = idp["issuer_url"].rstrip("/") + "/authorize?" + urlencode(params)
    logger.info("oidc_login: idp=%s redirect state=%s", idp_id, state)
    return RedirectResponse(url=authorize, status_code=302)


@router.post("/{idp_id}/callback")
async def oidc_callback(idp_id: str, req: OidcCallbackRequest, request: Request) -> dict[str, Any]:
    store = request.app.state.store
    idp = await store.get_idp(idp_id)
    if idp is None:
        raise HTTPException(status_code=404, detail="idp not found")
    tenant_id = idp["tenant_id"]
    if req.state and req.state in _STATES:
        st = _STATES.pop(req.state)
        if st["idp_id"] != idp_id:
            raise HTTPException(status_code=400, detail="state mismatch")
    kek = get_settings(request).kek
    client_secret = (
        decrypt_secret(idp["client_secret_enc"], kek) if idp["client_secret_enc"] else None
    )
    token_url = idp["issuer_url"].rstrip("/") + "/token"
    userinfo_url = idp["issuer_url"].rstrip("/") + "/userinfo"
    data = {
        "grant_type": "authorization_code",
        "code": req.code,
        "redirect_uri": _redirect_uri(request, idp_id),
        "client_id": idp.get("client_id") or "",
    }
    if client_secret:
        data["client_secret"] = client_secret
    async with httpx.AsyncClient(timeout=10) as cx:
        tresp = await cx.post(token_url, data=data)
        if tresp.status_code != 200:
            logger.warning("oidc_callback: token exchange failed %s", tresp.status_code)
            raise HTTPException(status_code=502, detail="idp token exchange failed")
        access_token = tresp.json().get("access_token")
        if not access_token:
            raise HTTPException(status_code=502, detail="idp returned no access_token")
        uresp = await cx.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
        if uresp.status_code != 200:
            logger.warning("oidc_callback: userinfo failed %s", uresp.status_code)
            raise HTTPException(status_code=502, detail="idp userinfo failed")
        userinfo = uresp.json()
    sub = userinfo.get("sub") or userinfo.get("email")
    if not sub:
        raise HTTPException(status_code=502, detail="idp userinfo missing sub/email")
    username = userinfo.get("email") or sub
    user = await store.get_user_by_username(username)
    if user is None:
        if not idp.get("auto_provision"):
            raise HTTPException(status_code=403, detail="auto_provision disabled; user not found")
        uid = "usr_" + secrets.token_hex(6)
        user = await store.create_user(
            uid, username, secrets.token_hex(16), must_change_password=False
        )
        logger.warning("oidc_callback: auto-provisioned user=%s tenant=%s", uid, tenant_id)
    else:
        uid = user["user_id"]
    role = await store.get_member_role(tenant_id, uid)
    if role is None:
        await store.add_member(tenant_id, uid, "member")
        role = "member"
        logger.info("oidc_callback: added membership user=%s tenant=%s", uid, tenant_id)
    svc = request.app.state.auth_service
    from fusion_identity.auth import _role_scopes

    scopes = _role_scopes(role)
    from fusion_identity.jwt_utils import issue_token

    access, jti = issue_token(
        sub=uid,
        tid=tenant_id,
        role=role,
        scopes=scopes,
        signing_key=svc._signing_key,
        issuer=svc._issuer,
        audience=svc._audience,
        ttl_seconds=svc._ttl,
        token_type="access",
        algorithm=svc._algorithm,
        kid=svc._kid,
    )
    refresh, rjti = issue_token(
        sub=uid,
        tid=tenant_id,
        role=role,
        scopes=scopes,
        signing_key=svc._signing_key,
        issuer=svc._issuer,
        audience=svc._audience,
        ttl_seconds=svc._refresh_ttl,
        token_type="refresh",
        algorithm=svc._algorithm,
        kid=svc._kid,
    )
    import time

    await store.insert_refresh_token(
        rjti, secrets.token_hex(8), tenant_id, uid, expires_at=time.time() + svc._refresh_ttl
    )
    await store.append_audit(
        tenant_id, uid, jti, role, "auth.oidc_login", "session", {"idp": idp_id}
    )
    logger.info("oidc_callback: issued tokens user=%s tenant=%s", uid, tenant_id)
    return {"access_token": access, "refresh_token": refresh, "expires_in": svc._ttl}


def _redirect_uri(request: Request, idp_id: str) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1/auth/oidc/{idp_id}/callback"
