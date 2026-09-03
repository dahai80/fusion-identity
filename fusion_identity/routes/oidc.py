from __future__ import annotations

import logging
import re
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

# M11: a username persisted from IdP email/sub must not carry control chars or
# whitespace that enable log injection or break downstream JWT sub/audit.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@\-]{1,128}$")


def _purge_states() -> None:
    now = time.time()
    expired = [k for k, v in _STATES.items() if now - v.get("ts", 0) > _STATES_TTL]
    for k in expired:
        _STATES.pop(k, None)


def _cache(request: Request):
    return getattr(request.app.state, "cache", None)


async def _put_state(request: Request, state: str, info: dict[str, Any]) -> None:
    # P2-2: prefer Redis so a callback landing on a different worker still
    # resolves the state. In-memory OrderedDict is the single-worker fallback.
    info = {**info, "ts": time.time()}
    cache = _cache(request)
    if cache is not None:
        try:
            await cache.put_oidc_state(state, info, _STATES_TTL)
            return
        except Exception as exc:
            logger.warning("oidc: redis put_state failed, fallback in-memory: %s", exc)
    _purge_states()
    _STATES[state] = info
    _STATES.move_to_end(state)
    while len(_STATES) > _STATES_MAX:
        _STATES.popitem(last=False)


async def _pop_state(request: Request, state: str) -> dict[str, Any] | None:
    cache = _cache(request)
    if cache is not None:
        try:
            info = await cache.pop_oidc_state(state)
            if info is not None:
                return info
            # absent in redis — do NOT consult in-memory: in a multi-worker
            # setup a None from redis is authoritative (state never existed or
            # already consumed). Fall through only on redis error (handled below).
            return None
        except Exception as exc:
            logger.warning("oidc: redis pop_state failed, fallback in-memory: %s", exc)
    _purge_states()
    st = _STATES.pop(state, None)
    if st is None:
        return None
    if time.time() - st.get("ts", 0) > _STATES_TTL:
        return None
    return st


def _sanitize_username(raw: str) -> str:
    cleaned = (raw or "").strip()
    if not _USERNAME_RE.match(cleaned):
        raise HTTPException(status_code=400, detail="invalid username from idp")
    return cleaned


@router.get("/{idp_id}/login")
async def oidc_login(idp_id: str, request: Request) -> RedirectResponse:
    store = request.app.state.store
    idp = await store.get_idp(idp_id)
    if idp is None:
        raise HTTPException(status_code=404, detail="idp not found")
    if not idp.get("issuer_url"):
        raise HTTPException(status_code=400, detail="idp missing issuer_url")
    state = secrets.token_hex(8)
    # F3: PKCE — store a code_verifier, send a code_challenge so the token
    # exchange is bound to this login initiation (CSRF + login-fixation defense
    # alongside the mandatory state check).
    code_verifier = secrets.token_urlsafe(48)
    # P2-1: nonce binds the id_token to this login (replay defense).
    nonce = secrets.token_urlsafe(24)
    await _put_state(
        request,
        state,
        {
            "idp_id": idp_id,
            "tenant_id": idp["tenant_id"],
            "code_verifier": code_verifier,
            "nonce": nonce,
        },
    )
    disc = await _discovery(idp["issuer_url"])
    params = {
        "response_type": "code",
        "client_id": idp.get("client_id") or "",
        "redirect_uri": _redirect_uri(request, idp_id),
        "scope": idp.get("scopes") or "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": _pkce_challenge(code_verifier),
        "code_challenge_method": "S256",
    }
    authorize = disc["authorization_endpoint"] + "?" + urlencode(params)
    logger.info("oidc_login: idp=%s redirect state=%s", idp_id, state)
    return RedirectResponse(url=authorize, status_code=302)


def _pkce_challenge(verifier: str) -> str:
    import base64
    import hashlib

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# P2-1: IdP discovery cache. Resolves standard OIDC endpoints from the issuer's
# /.well-known/openid-configuration instead of hardcoding /authorize /token
# /userinfo. Falls back to constructed paths when the IdP has no discovery doc
# (legacy OAuth2 IdPs), so existing integrations do not break.
_DISCOVERY: dict[str, dict[str, Any]] = {}
# C2: PyJWKClient is cached per jwks_uri so the JWKS document is fetched once
# per IdP, not on every callback (the prior per-call instantiation re-fetched
# JWKS each time — a measurable hot-path cost). PyJWKClient itself caches the
# parsed keys internally and refreshes on kid miss.
_JWKS_CLIENTS: dict[str, Any] = {}


async def _discovery(issuer_url: str) -> dict[str, str]:
    issuer = issuer_url.rstrip("/")
    cached = _DISCOVERY.get(issuer)
    if cached is not None:
        return cached
    doc_url = issuer + "/.well-known/openid-configuration"
    fallback = {
        "issuer": issuer,
        "authorization_endpoint": issuer + "/authorize",
        "token_endpoint": issuer + "/token",
        "userinfo_endpoint": issuer + "/userinfo",
        "jwks_uri": issuer + "/jwks",
    }
    try:
        async with httpx.AsyncClient(timeout=10) as cx:
            dresp = await cx.get(doc_url)
            if dresp.status_code != 200:
                logger.warning(
                    "oidc: discovery %s returned %s, using fallback paths",
                    doc_url,
                    dresp.status_code,
                )
                _DISCOVERY[issuer] = fallback
                return fallback
            doc = dresp.json()
    except Exception as exc:
        logger.warning("oidc: discovery fetch failed (%s), using fallback paths", exc)
        _DISCOVERY[issuer] = fallback
        return fallback
    resolved = {
        "issuer": doc.get("issuer", issuer),
        "authorization_endpoint": doc.get(
            "authorization_endpoint", fallback["authorization_endpoint"]
        ),
        "token_endpoint": doc.get("token_endpoint", fallback["token_endpoint"]),
        "userinfo_endpoint": doc.get("userinfo_endpoint", fallback["userinfo_endpoint"]),
        "jwks_uri": doc.get("jwks_uri", fallback["jwks_uri"]),
    }
    _DISCOVERY[issuer] = resolved
    logger.info("oidc: discovery resolved issuer=%s endpoints=%s", issuer, list(resolved))
    return resolved


async def _verify_id_token(
    id_token: str, disc: dict[str, str], client_id: str, nonce: str | None
) -> dict[str, Any] | None:
    # P2-1: verify the id_token JWT — signature via the IdP JWKS (PyJWKClient),
    # plus iss/aud/exp/nonce claims. Returns the claims, or None when the IdP
    # did not return an id_token (legacy OAuth2) so the caller falls back to
    # userinfo. A present-but-invalid id_token raises (fail-closed).
    import jwt as pyjwt
    from jwt import PyJWKClient

    jwks_uri = disc.get("jwks_uri")
    if not jwks_uri:
        logger.warning("oidc: id_token present but no jwks_uri — cannot verify")
        raise HTTPException(status_code=502, detail="idp jwks_uri missing")
    signing_algos = ["RS256", "ES256", "RS384", "RS512"]
    try:
        jwks_client = _JWKS_CLIENTS.get(jwks_uri)
        if jwks_client is None:
            jwks_client = PyJWKClient(jwks_uri, timeout=10)
            _JWKS_CLIENTS[jwks_uri] = jwks_client
            logger.info("oidc: PyJWKClient created for jwks_uri=%s", jwks_uri)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = pyjwt.decode(
            id_token,
            signing_key.key,
            algorithms=signing_algos,
            audience=client_id,
            issuer=disc.get("issuer"),
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("oidc: id_token verification failed: %s", exc)
        raise HTTPException(status_code=401, detail="id_token verification failed") from exc
    if nonce is not None and claims.get("nonce") != nonce:
        logger.warning("oidc: id_token nonce mismatch (replay?)")
        raise HTTPException(status_code=401, detail="id_token nonce mismatch")
    return claims


@router.post("/{idp_id}/callback")
async def oidc_callback(idp_id: str, req: OidcCallbackRequest, request: Request) -> dict[str, Any]:
    store = request.app.state.store
    idp = await store.get_idp(idp_id)
    if idp is None:
        raise HTTPException(status_code=404, detail="idp not found")
    tenant_id = idp["tenant_id"]
    # F3: state is MANDATORY — an omitted or unknown state means the auth-code
    # was not initiated by us (CSRF / login-fixation). Reject rather than skip.
    # P6: also reject expired states (purge first so stale entries are gone).
    if not req.state:
        raise HTTPException(status_code=400, detail="missing state (csrf protection required)")
    st = await _pop_state(request, req.state)
    if st is None:
        raise HTTPException(status_code=400, detail="unknown or expired state")
    if time.time() - st.get("ts", 0) > _STATES_TTL:
        raise HTTPException(status_code=400, detail="state expired")
    if st.get("idp_id") != idp_id:
        raise HTTPException(status_code=400, detail="state mismatch")
    code_verifier = st.get("code_verifier")
    nonce = st.get("nonce")
    kek = get_settings(request).kek
    client_secret = (
        decrypt_secret(idp["client_secret_enc"], kek) if idp["client_secret_enc"] else None
    )
    disc = await _discovery(idp["issuer_url"])
    token_url = disc["token_endpoint"]
    userinfo_url = disc["userinfo_endpoint"]
    data = {
        "grant_type": "authorization_code",
        "code": req.code,
        "redirect_uri": _redirect_uri(request, idp_id),
        "client_id": idp.get("client_id") or "",
    }
    if client_secret:
        data["client_secret"] = client_secret
    # F3: PKCE — prove the callback belongs to the login that started it.
    if code_verifier:
        data["code_verifier"] = code_verifier
    async with httpx.AsyncClient(timeout=10) as cx:
        tresp = await cx.post(token_url, data=data)
        if tresp.status_code != 200:
            logger.warning("oidc_callback: token exchange failed %s", tresp.status_code)
            raise HTTPException(status_code=502, detail="idp token exchange failed")
        tjson = tresp.json()
        access_token = tjson.get("access_token")
        if not access_token:
            raise HTTPException(status_code=502, detail="idp returned no access_token")
        # P2-1: verify id_token when present (true OIDC). Fall back to userinfo
        # for legacy OAuth2 IdPs that return no id_token.
        id_claims = None
        id_token = tjson.get("id_token")
        if id_token:
            id_claims = await _verify_id_token(id_token, disc, idp.get("client_id") or "", nonce)
            logger.info("oidc_callback: id_token verified sub=%s", id_claims.get("sub"))
        if id_claims is not None:
            userinfo = id_claims
        else:
            uresp = await cx.get(userinfo_url, headers={"Authorization": f"Bearer {access_token}"})
            if uresp.status_code != 200:
                logger.warning("oidc_callback: userinfo failed %s", uresp.status_code)
                raise HTTPException(status_code=502, detail="idp userinfo failed")
            userinfo = uresp.json()
    sub = userinfo.get("sub") or userinfo.get("email")
    if not sub:
        raise HTTPException(status_code=502, detail="idp userinfo missing sub/email")
    # M11: sanitize before persisting as username / JWT sub.
    username = _sanitize_username(userinfo.get("email") or sub)
    user = await store.get_user_by_username(username)
    if user is None:
        if not idp.get("auto_provision"):
            raise HTTPException(status_code=403, detail="auto_provision disabled; user not found")
        uid = "usr_" + secrets.token_hex(6)
        user = await store.create_user(
            uid, username, secrets.token_hex(16), must_change_password=False
        )
        logger.warning("oidc_callback: auto-provisioned user=%s tenant=%s", uid, tenant_id)
        # L22: a newly provisioned user has no membership yet — add it.
        await store.add_member(tenant_id, uid, "member")
    else:
        # L22: do NOT auto-add an existing (possibly cross-tenant) user as a
        # member of this tenant. Only users this tenant already knows keep
        # their role; a global username reuse must not grant membership.
        uid = user["user_id"]
    role = await store.get_member_role(tenant_id, uid)
    if role is None:
        # Existing user with no prior membership is NOT auto-granted one —
        # operator must explicitly add them. Fail-closed.
        raise HTTPException(
            status_code=403, detail="user not a member of this tenant; add membership first"
        )
    svc = request.app.state.auth_service
    from fusion_identity.auth import _role_scopes

    scopes = _role_scopes(role)
    from fusion_identity.jwt_utils import issue_token

    access, jti = issue_token(
        sub=uid,
        tid=tenant_id,
        role=role,
        scopes=scopes,
        signing_key=svc._signing_key(),
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
        signing_key=svc._signing_key(),
        issuer=svc._issuer,
        audience=svc._audience,
        ttl_seconds=svc._refresh_ttl,
        token_type="refresh",
        algorithm=svc._algorithm,
        kid=svc._kid,
    )
    await store.insert_refresh_token(
        rjti, secrets.token_hex(8), tenant_id, uid, expires_at=time.time() + svc._refresh_ttl
    )
    await store.record_issued_jti(jti, tenant_id, uid)
    await store.append_audit(
        tenant_id, uid, jti, role, "auth.oidc_login", "session", {"idp": idp_id}
    )
    logger.info("oidc_callback: issued tokens user=%s tenant=%s", uid, tenant_id)
    return {"access_token": access, "refresh_token": refresh, "expires_in": svc._ttl}


def _redirect_uri(request: Request, idp_id: str) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1/auth/oidc/{idp_id}/callback"
