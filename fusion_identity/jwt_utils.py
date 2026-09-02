from __future__ import annotations

import logging
import secrets
from typing import Any

import jwt

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"


class JwtError(Exception):
    pass


def issue_token(
    *,
    sub: str,
    tid: str,
    role: str,
    scopes: list[str],
    signing_key: str,
    issuer: str,
    audience: str,
    ttl_seconds: int,
    token_type: str = "access",
) -> tuple[str, str]:
    now = int(__import__("time").time())
    jti = secrets.token_hex(12)
    payload: dict[str, Any] = {
        "sub": sub,
        "tid": tid,
        "tenant": tid,
        "role": role,
        "scope": scopes,
        "iat": now,
        "iss": issuer,
        "aud": audience,
        "jti": jti,
        "type": token_type,
    }
    if token_type == "refresh":
        payload["exp"] = now + ttl_seconds
    else:
        payload["exp"] = now + ttl_seconds
    token = jwt.encode(payload, signing_key, algorithm=ALGORITHM)
    logger.info(
        "issue_token: sub=%s tid=%s role=%s type=%s jti=%s", sub, tid, role, token_type, jti
    )
    return token, jti


def verify_token(
    token: str, signing_key: str, issuer: str, audience: str, *, token_type: str | None = None
) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=[ALGORITHM],
            issuer=issuer,
            audience=audience,
            options={"require": ["exp", "iat", "iss", "aud", "jti", "sub", "tid"]},
        )
    except jwt.PyJWTError as exc:
        logger.warning("verify_token: rejected: %s", exc)
        raise JwtError(f"invalid token: {exc}") from exc
    if token_type is not None and claims.get("type") != token_type:
        logger.warning("verify_token: type mismatch want=%s got=%s", token_type, claims.get("type"))
        raise JwtError(f"token type mismatch: expected {token_type}")
    return claims


def extract_bearer(header: str) -> str:
    if not header:
        raise JwtError("missing authorization header")
    lower = header.lower()
    if not lower.startswith("bearer "):
        raise JwtError("authorization header must be Bearer")
    return header[7:].strip()
