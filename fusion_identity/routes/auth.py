from __future__ import annotations

import hashlib
import logging
import secrets
import time

from fastapi import APIRouter, Depends, HTTPException, Request

from fusion_identity import metrics_collector as mc
from fusion_identity.auth import AuthService
from fusion_identity.deps import (
    get_auth_service,
    get_settings,
    get_store,
    require_bearer,
    require_service_token,
)
from fusion_identity.email_sender import EmailDeliveryError, send_password_reset_email
from fusion_identity.jwt_utils import JwtError
from fusion_identity.models import (
    LoginRequest,
    LogoutRequest,
    PasswordChangeRequest,
    PasswordForgotRequest,
    PasswordResetConfirmRequest,
    RefreshRequest,
    RevokeRequest,
    SessionIssueRequest,
    SessionRevokeRequest,
    SessionVerifyRequest,
    SsoTicketExchangeRequest,
    SsoTicketIssueResponse,
    TokenResponse,
    VerifyRequest,
    VerifyResponse,
)
from fusion_identity.ratelimit import check_login_rate
from fusion_identity.store import hash_password

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    req: LoginRequest,
    request: Request,
    svc: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    await check_login_rate(request, req.tenant_id, req.username)
    try:
        resp = await svc.login(req)
        # P3-1: the auth_requests_total counter only recorded gRPC authorize
        # calls; HTTP logins were invisible to monitoring. Record here too.
        mc.record_auth(req.tenant_id, "http", "login_ok", 200)
        return resp
    except HTTPException as exc:
        mc.record_auth(req.tenant_id, "http", "login_fail", exc.status_code)
        raise


@router.get("/verify", response_model=VerifyResponse, dependencies=[Depends(require_service_token)])
async def verify(
    token: str,
    svc: AuthService = Depends(get_auth_service),
) -> VerifyResponse:
    try:
        return await svc.verify(VerifyRequest(token=token))
    except JwtError as exc:
        logger.info("verify GET: rejected token: %s", exc)
        raise HTTPException(status_code=401, detail="invalid token") from exc


@router.post(
    "/verify", response_model=VerifyResponse, dependencies=[Depends(require_service_token)]
)
async def verify_post(
    req: VerifyRequest, svc: AuthService = Depends(get_auth_service)
) -> VerifyResponse:
    try:
        return await svc.verify(req)
    except JwtError as exc:
        logger.info("verify POST: rejected token: %s", exc)
        raise HTTPException(status_code=401, detail="invalid token") from exc


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    req: RefreshRequest, svc: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    return await svc.refresh(req)


@router.post("/revoke")
async def revoke(
    req: RevokeRequest,
    claims: dict = Depends(require_bearer),
    svc: AuthService = Depends(get_auth_service),
) -> dict:
    if claims.get("role") != "tenant_admin":
        raise HTTPException(status_code=403, detail="tenant_admin role required")
    return await svc.revoke(req, claims["tid"], claims.get("sub"))


@router.post("/logout")
async def logout(
    req: LogoutRequest,
    claims: dict = Depends(require_bearer),
    svc: AuthService = Depends(get_auth_service),
) -> dict:
    return await svc.logout(claims, req.refresh_token)


@router.post("/password")
async def change_password(
    req: PasswordChangeRequest,
    claims: dict = Depends(require_bearer),
    svc: AuthService = Depends(get_auth_service),
) -> dict:
    return await svc.change_password(
        claims["sub"], req.old_password, req.new_password, tenant_id=claims["tid"]
    )


@router.post("/session", dependencies=[Depends(require_service_token)])
async def issue_session(
    req: SessionIssueRequest, svc: AuthService = Depends(get_auth_service)
) -> dict:
    # Issue #9 (Union Web R-2): gateway-issued browser session token.
    try:
        return await svc.issue_session_token(
            req.sub,
            tenant_id=req.tenant_id,
            role=req.role,
            ttl_seconds=req.ttl_seconds,
        )
    except HTTPException as exc:
        logger.info("issue_session: refused: %s", exc.detail)
        raise


@router.delete("/sessions", dependencies=[Depends(require_service_token)])
async def revoke_user_sessions(
    req: SessionRevokeRequest, svc: AuthService = Depends(get_auth_service)
) -> dict:
    # Issue #29: user-deletion flow for business apps (App Store requirement:
    # account deletion must invalidate credentials, not just delete rows).
    # Revokes every unexpired access/session jti plus all refresh-token
    # families for (sub, tenant_id). Service-token gated, fail-closed.
    return await svc.revoke_user_sessions_and_tokens(req.sub, req.tenant_id)


@router.post("/session/verify", dependencies=[Depends(require_service_token)])
async def verify_session(
    req: SessionVerifyRequest, svc: AuthService = Depends(get_auth_service)
) -> dict:
    # Gateway-side validation of a shell session token (issue #9).
    try:
        claims = await svc.verify_session_token(req.token)
    except JwtError as exc:
        logger.info("verify_session: rejected token: %s", exc)
        raise HTTPException(status_code=401, detail="invalid session token") from exc
    return {
        "valid": True,
        "sub": claims["sub"],
        "tid": claims["tid"],
        "tenant": claims.get("tenant"),
        "role": claims["role"],
        "scope": claims.get("scope", []),
        "iat": claims.get("iat"),
        "exp": claims.get("exp"),
        "jti": claims["jti"],
        "type": claims.get("type"),
    }


@router.post(
    "/introspect",
    dependencies=[Depends(require_service_token)],
    response_model_exclude_none=True,
)
async def introspect(
    request: Request,
    svc: AuthService = Depends(get_auth_service),
) -> dict:
    import json

    # L18: cap the raw request body up front so neither the form nor the JSON
    # branch can be forced to buffer an unbounded payload on this
    # service-token endpoint.
    raw = await request.body()
    if len(raw) > 32768:
        raise HTTPException(status_code=413, detail="introspect body too large")
    body: dict = {}
    ctype = (request.headers.get("content-type") or "").lower()
    if "application/x-www-form-urlencoded" in ctype:
        form = await request.form()
        token = form.get("token") or ""
    else:
        # decode defensively so a non-UTF-8 payload cannot crash with a 500
        text = raw.decode("utf-8", errors="replace")
        try:
            body = json.loads(text or "{}")
        except json.JSONDecodeError:
            body = {}
        token = body.get("token") or ""
    if not token:
        return {"active": False}
    return await svc.introspect(token)


@router.post("/ticket", response_model=SsoTicketIssueResponse)
async def issue_sso_ticket(
    request: Request,
    claims: dict = Depends(require_bearer),
    svc: AuthService = Depends(get_auth_service),
) -> SsoTicketIssueResponse:
    # Issue #48: mint a one-time SSO ticket for the caller's session
    # (fusion-site → web-shell handoff). The tenant middleware already
    # verified X-Tenant-Id == token tid for this non-exempt path; the ticket
    # is bound to the session's sub + tenant. Role is advisory here — the
    # exchange re-fetches it from tenant_members.
    logger.info("sso ticket route: issue sub=%s tid=%s", claims.get("sub"), claims.get("tid"))
    out = await svc.issue_sso_ticket(claims["sub"], claims["tid"], claims.get("role", "member"))
    return SsoTicketIssueResponse(ticket=out["ticket"], expires_in=out["expires_in"])


@router.post("/ticket/exchange", response_model=TokenResponse)
async def exchange_sso_ticket(
    request: Request,
    req: SsoTicketExchangeRequest,
    svc: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    # Issue #48: exchange a one-time SSO ticket for the standard token pair.
    # Tenant-middleware-exempt (the ticket itself is the secret); rate-limited
    # like login against a pseudo tenant key.
    await check_login_rate(request, "_sso_ticket", None)
    return await svc.exchange_sso_ticket(req.ticket)


def _mask_email(email: str) -> str:
    name, _, domain = email.partition("@")
    if not domain:
        return "***"
    shown = name[:2] if len(name) > 2 else name[:1]
    return f"{shown}***@{domain}"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@router.post("/password/forgot")
async def forgot_password(
    request: Request,
    body: PasswordForgotRequest,
    store=Depends(get_store),
    settings=Depends(get_settings),
) -> dict:
    # Issue #54: request a password reset. Default response is ALWAYS
    # {"sent": true} — account existence never leaves this endpoint (no
    # enumeration). With settings.password_forgot_reveal_missing enabled
    # (issue #58), unknown emails return 404 and SMTP delivery failures
    # return 502 instead of a fake "sent" confirmation.
    # Rate-limited per email pseudo key.
    await check_login_rate(request, "_pw_forgot", body.email)
    email = body.email.strip()
    user = await store.get_user_by_email(email)
    if user is None:
        if settings.password_forgot_reveal_missing:
            logger.info("forgot_password: no account for %s (explicit 404)", _mask_email(email))
            raise HTTPException(status_code=404, detail="no account for this email")
        logger.info("forgot_password: no account for %s (uniform response)", _mask_email(email))
        return {"sent": True}
    token = secrets.token_urlsafe(32)
    ok = await store.set_password_reset_token(
        user["user_id"],
        _hash_token(token),
        time.time() + settings.password_reset_ttl_seconds,
    )
    if ok:
        try:
            await send_password_reset_email(settings, email, token, user["username"])
        except EmailDeliveryError:
            if settings.password_forgot_reveal_missing:
                logger.warning(
                    "forgot_password: delivery failed user=%s (explicit 502)", user["user_id"]
                )
                raise HTTPException(
                    status_code=502, detail="mail delivery failed; retry shortly"
                ) from None
            # Delivery failure must not leak account existence via the
            # response — the user can simply request again.
            logger.warning("forgot_password: delivery failed user=%s", user["user_id"])
    else:
        logger.error("forgot_password: failed to arm reset token user=%s", user["user_id"])
    return {"sent": True}


@router.post("/password/reset")
async def reset_password(
    request: Request,
    body: PasswordResetConfirmRequest,
    store=Depends(get_store),
) -> dict:
    # Issue #54: consume a single-use reset token and set the new password.
    # Tenant-middleware-exempt (the token is the secret); uniform 400 for
    # unknown/expired/replayed tokens. Mirrors change_password: rotate the
    # argon2id hash, revoke every refresh token family so old sessions die.
    await check_login_rate(request, "_pw_reset", None)
    user_id = await store.consume_password_reset_token(_hash_token(body.token))
    if user_id is None:
        logger.warning("reset_password: invalid, expired, or replayed token")
        raise HTTPException(status_code=400, detail="invalid or expired reset token")
    pw_hash, salt, algo = hash_password(body.new_password)
    await store.update_user(
        user_id,
        password_hash_v=pw_hash,
        salt=salt,
        password_algo=algo,
        must_change_password=False,
    )
    revoked = await store.revoke_user_sessions(user_id)
    try:
        await store.append_audit(
            tenant_id="_system",
            user_id=user_id,
            jti=None,
            role="public",
            action="auth.password_reset",
            resource=None,
            detail={"via": "self_service"},
        )
    except Exception:
        logger.exception("reset_password: audit append failed user=%s", user_id)
    logger.info("reset_password: user=%s revoked_sessions=%s", user_id, revoked)
    return {"reset": True}
