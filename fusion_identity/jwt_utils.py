from __future__ import annotations

import logging
import secrets
import time
from typing import Any

import jwt

logger = logging.getLogger(__name__)

ALGORITHMS = ["HS256", "RS256"]


class JwtError(Exception):
    pass


def jwt_get_unverified_header(token: str) -> dict[str, Any]:
    try:
        return jwt.get_unverified_header(token)
    except Exception as exc:
        raise JwtError(f"invalid token header: {exc}") from exc


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
    algorithm: str = "HS256",
    kid: str | None = None,
) -> tuple[str, str]:
    now = int(time.time())
    jti = secrets.token_hex(12)
    payload: dict[str, Any] = {
        "sub": sub,
        "tid": tid,
        "tenant": tid,
        "role": role,
        "scope": scopes,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "iss": issuer,
        "aud": audience,
        "jti": jti,
        "type": token_type,
    }
    headers: dict[str, str] = {}
    if kid and algorithm == "RS256":
        headers["kid"] = kid
    token = jwt.encode(payload, signing_key, algorithm=algorithm, headers=headers or None)
    logger.info(
        "issue_token: sub=%s tid=%s role=%s type=%s alg=%s jti=%s",
        sub,
        tid,
        role,
        token_type,
        algorithm,
        jti,
    )
    return token, jti


def verify_token(
    token: str,
    signing_key: str,
    issuer: str,
    audience: str,
    *,
    token_type: str | None = None,
    algorithms: list[str] | None = None,
    kid: str | None = None,
) -> dict[str, Any]:
    algos = algorithms or ALGORITHMS
    try:
        claims = jwt.decode(
            token,
            signing_key,
            algorithms=algos,
            issuer=issuer,
            audience=audience,
            options={"require": ["exp", "iat", "iss", "aud", "jti", "sub", "tid"]},
        )
    except jwt.PyJWTError as exc:
        logger.warning("verify_token: rejected: %s", exc)
        raise JwtError(f"invalid token: {exc}") from exc
    except (ValueError, TypeError) as exc:
        logger.warning("verify_token: malformed token: %s", exc)
        raise JwtError("invalid token: malformed") from exc
    if token_type is not None and claims.get("type") != token_type:
        logger.warning("verify_token: type mismatch want=%s got=%s", token_type, claims.get("type"))
        raise JwtError(f"token type mismatch: expected {token_type}")
    logger.debug("verify_token: ok kid=%s", kid)
    return claims


def extract_bearer(header: str) -> str:
    if not header:
        raise JwtError("missing authorization header")
    lower = header.lower()
    if not lower.startswith("bearer "):
        raise JwtError("authorization header must be Bearer")
    return header[7:].strip()
