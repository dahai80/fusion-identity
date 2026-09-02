from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

GRACE_SECONDS = 24 * 3600


@dataclass
class _RsaKey:
    kid: str
    private_pem: str
    public_pem: str
    created_at: float


def _rsa_key_to_dict(rk: _RsaKey) -> dict[str, Any]:
    return {
        "kid": rk.kid,
        "private_pem": rk.private_pem,
        "public_pem": rk.public_pem,
        "created_at": rk.created_at,
    }


def _rsa_key_from_dict(d: dict[str, Any]) -> _RsaKey | None:
    kid = d.get("kid")
    pub = d.get("public_pem")
    if not kid or not pub:
        return None
    return _RsaKey(
        kid=kid,
        private_pem=d.get("private_pem") or "",
        public_pem=pub,
        created_at=float(d.get("created_at") or 0.0),
    )


def _generate_rsa_pair(kid: str) -> _RsaKey:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return _RsaKey(kid=kid, private_pem=private_pem, public_pem=public_pem, created_at=time.time())


def _b64u_int(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def _kid_for_pem(public_pem: str) -> str:
    # L13: deterministic kid derived from the public key DER so it is stable
    # across restarts rather than random (random kid breaks cached verifiers).
    der = public_pem.encode()
    digest = hashlib.sha256(der).digest()
    return _b64u_int(int.from_bytes(digest[:10], "big"))[:16]


def _rsa_public_jwk(kid: str, public_pem: str) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pub = serialization.load_pem_public_key(public_pem.encode())
    # M2: assert is stripped under `python -O`; raise explicitly instead.
    if not isinstance(pub, rsa.RSAPublicKey):
        logger.error("_rsa_public_jwk: not an RSA public key (kid=%s)", kid)
        raise ValueError(f"not an RSA public key (kid={kid})")
    numbers = pub.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _b64u_int(numbers.n),
        "e": _b64u_int(numbers.e),
    }


@dataclass
class KeyRing:
    algorithm: str = "HS256"
    hs_key: str = ""
    rsa_current: _RsaKey | None = None
    # L14: retired keys kept as a timestamped list (not a single overwritten
    # slot) so multiple rotations within the grace window are all still
    # verifiable. Older-than-grace keys are pruned by prune().
    rsa_retired: list[_RsaKey] = field(default_factory=list)
    _kid_index: dict[str, _RsaKey] = field(default_factory=dict)
    # P0-1: persistence path. When set, rotation state (current + retired keys)
    # is atomically written here and recovered on restart so a rotated key does
    # not silently disappear (which makes tokens signed by it unverifiable).
    persist_path: str = ""

    @classmethod
    def hs256(cls, key: str) -> KeyRing:
        return cls(algorithm="HS256", hs_key=key)

    def _persist(self) -> None:
        # P0-1: atomically write current + retired keys so a restart recovers
        # the full rotation history. tmp file + rename = crash-safe.
        if not self.persist_path or self.algorithm != "RS256":
            return
        if not self.rsa_current:
            return
        payload = {
            "algorithm": self.algorithm,
            "current": _rsa_key_to_dict(self.rsa_current),
            "retired": [_rsa_key_to_dict(rk) for rk in self.rsa_retired],
        }
        directory = os.path.dirname(os.path.abspath(self.persist_path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".keyring_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump(payload, fh)
            os.replace(tmp, self.persist_path)
            logger.info("KeyRing: persisted rotation state to %s", self.persist_path)
        except Exception as exc:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            logger.error("KeyRing: persist failed (%s) — rotation NOT durable", exc)

    @classmethod
    def _load_persisted(cls, persist_path: str) -> KeyRing | None:
        # P0-1: recover current + retired keys from a prior rotation so tokens
        # signed by a rotated key stay verifiable across restarts.
        if not persist_path or not os.path.exists(persist_path):
            return None
        try:
            with open(persist_path) as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("KeyRing: corrupt persist file %s (%s) — ignoring", persist_path, exc)
            return None
        if payload.get("algorithm") != "RS256":
            return None
        cur = _rsa_key_from_dict(payload.get("current") or {})
        retired = [_rsa_key_from_dict(d) for d in payload.get("retired") or []]
        retired = [rk for rk in retired if rk is not None]
        if cur is None:
            return None
        ring = cls(
            algorithm="RS256",
            rsa_current=cur,
            rsa_retired=retired,
            persist_path=persist_path,
        )
        ring._kid_index[cur.kid] = cur
        for rk in retired:
            ring._kid_index[rk.kid] = rk
        logger.info(
            "KeyRing: recovered persisted rotation kid=%s retired=%d from %s",
            cur.kid,
            len(retired),
            persist_path,
        )
        return ring

    @classmethod
    def rs256(
        cls,
        private_pem: str | None = None,
        public_keys_pem: str | None = None,
        persist_path: str = "",
    ) -> KeyRing:
        # P0-1: prefer a persisted rotation state so a restart does not roll
        # back a rotation (which would make rotated-key tokens unverifiable).
        if persist_path:
            recovered = cls._load_persisted(persist_path)
            if recovered is not None:
                if public_keys_pem:
                    recovered._load_extra_public_keys(public_keys_pem)
                return recovered
        if private_pem:
            from cryptography.hazmat.primitives import serialization

            priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
            public_pem = (
                priv.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode()
            )
            kid = _kid_for_pem(public_pem)
            rk = _RsaKey(
                kid=kid, private_pem=private_pem, public_pem=public_pem, created_at=time.time()
            )
        else:
            # No material supplied — generate a fresh pair. kid is random here
            # because the key itself is fresh each start (not a stable input).
            import secrets

            kid = "kid-" + secrets.token_hex(4)
            rk = _generate_rsa_pair(kid)
        ring = cls(algorithm="RS256", rsa_current=rk, persist_path=persist_path)
        ring._kid_index[rk.kid] = rk
        if public_keys_pem:
            ring._load_extra_public_keys(public_keys_pem)
        logger.info("KeyRing: rs256 initialized kid=%s", kid)
        return ring

    def _load_extra_public_keys(self, public_keys_pem: str) -> None:
        from cryptography.hazmat.primitives import serialization

        blocks = [b for b in public_keys_pem.split("-----END PUBLIC KEY-----") if "BEGIN" in b]
        for block in blocks:
            pem = block.strip() + "\n-----END PUBLIC KEY-----"
            try:
                serialization.load_pem_public_key(pem.encode())
                # L13: deterministic kid from the public key, not random.
                ekid = "kid-ext-" + _kid_for_pem(pem)
                self._kid_index[ekid] = _RsaKey(
                    kid=ekid,
                    private_pem="",
                    public_pem=pem,
                    created_at=time.time(),
                )
                logger.info("KeyRing: loaded extra public key kid=%s", ekid)
            except Exception as exc:
                logger.warning("KeyRing: skip invalid public key block: %s", exc)

    @property
    def kid(self) -> str | None:
        return self.rsa_current.kid if self.rsa_current else None

    def signing_key(self) -> str:
        if self.algorithm == "RS256" and self.rsa_current:
            return self.rsa_current.private_pem
        return self.hs_key

    def verify_key_for(self, kid: str | None) -> str:
        # M3: do NOT fall back to the current key on an unknown/missing kid.
        # A token with no kid, or a kid we do not recognize, must be rejected
        # rather than silently validated against whatever key happens to be
        # current. HS256 is symmetric so kid is irrelevant there.
        if self.algorithm == "HS256":
            return self.hs_key
        if kid and kid in self._kid_index:
            return self._kid_index[kid].public_pem
        from fusion_identity.jwt_utils import JwtError

        logger.warning("verify_key_for: unknown kid=%r — rejecting (M3)", kid)
        raise JwtError(f"unknown key id: {kid!r}")

    def rotate(self) -> str | None:
        if self.algorithm != "RS256" or not self.rsa_current:
            return None
        import secrets

        new_kid = "kid-" + secrets.token_hex(4)
        new_key = _generate_rsa_pair(new_kid)
        # L14: retire the current key into the retired list (append, do not
        # overwrite a single previous slot) so older-but-still-graced keys
        # remain verifiable.
        self.rsa_retired.append(self.rsa_current)
        self.rsa_current = new_key
        self._kid_index[new_key.kid] = new_key
        logger.info(
            "KeyRing: rotated kid new=%s retired=%d",
            new_kid,
            len(self.rsa_retired),
        )
        # P0-1: durably persist so a restart recovers the retired key.
        self._persist()
        return new_kid

    def prune(self) -> int:
        # L14: prune every retired key older than the grace window, not just a
        # single previous slot.
        now = time.time()
        keep: list[_RsaKey] = []
        dropped = 0
        for rk in self.rsa_retired:
            if now - rk.created_at > GRACE_SECONDS:
                self._kid_index.pop(rk.kid, None)
                logger.info("KeyRing: pruned expired retired kid=%s", rk.kid)
                dropped += 1
            else:
                keep.append(rk)
        self.rsa_retired = keep
        # P0-1: persist the pruned state so a restart does not resurrect a
        # retired key that should have aged out of the grace window.
        if dropped:
            self._persist()
        return dropped

    def jwks(self) -> dict[str, Any]:
        keys: list[dict[str, Any]] = []
        if self.rsa_current:
            keys.append(_rsa_public_jwk(self.rsa_current.kid, self.rsa_current.public_pem))
        # L14: publish all retired keys still in the grace window.
        for rk in self.rsa_retired:
            keys.append(_rsa_public_jwk(rk.kid, rk.public_pem))
        return {"keys": keys}
