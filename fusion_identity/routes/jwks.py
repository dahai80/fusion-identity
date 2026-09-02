from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from fusion_identity.deps import require_service_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["jwks"])


@router.get("/.well-known/jwks.json", include_in_schema=False)
async def get_jwks(request: Request) -> JSONResponse:
    svc = request.app.state.auth_service
    key_ring = getattr(svc, "_key_ring", None)
    if key_ring is None:
        logger.warning("jwks: no key_ring configured")
        return JSONResponse({"keys": []})
    key_ring.prune()
    doc = key_ring.jwks()
    logger.info("jwks: served keys=%d alg=%s", len(doc.get("keys", [])), key_ring.algorithm)
    return JSONResponse(doc)


@router.post("/.well-known/jwks/rotate", include_in_schema=False)
async def rotate_keys(request: Request, _: None = Depends(require_service_token)) -> JSONResponse:
    svc = request.app.state.auth_service
    key_ring = getattr(svc, "_key_ring", None)
    if key_ring is None:
        raise HTTPException(status_code=500, detail="no key_ring configured")
    new_kid = key_ring.rotate()
    if new_kid is None:
        raise HTTPException(status_code=400, detail="rotation requires RS256")
    # F17: signing_key/kid/algorithm are read live from the key ring, so no
    # snapshot fields need updating here — rotate() is the source of truth.
    logger.warning("jwks: rotated to new kid=%s", new_kid)
    # M9: key rotation is a security-sensitive, non-reversible operation — it
    # must leave an audit trail. Attribute it to the service principal since
    # this endpoint is service-token gated.
    store = getattr(request.app.state, "store", None)
    if store is not None:
        try:
            await store.append_audit(
                "default",
                "system",
                None,
                "operator",
                "jwks.rotate",
                "key",
                {"new_kid": new_kid, "algorithm": key_ring.algorithm},
            )
        except Exception as exc:
            logger.error("jwks rotate: audit write failed err=%s", exc)
    return JSONResponse({"rotated": True, "kid": new_kid, "jwks": key_ring.jwks()})
