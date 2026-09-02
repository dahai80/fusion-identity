from __future__ import annotations

import logging
import secrets
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


def _rsa_public_jwk(kid: str, public_pem: str) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    pub = serialization.load_pem_public_key(public_pem.encode())
    assert isinstance(pub, rsa.RSAPublicKey)
    numbers = pub.public_numbers()
    import base64

    def _b64u(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _b64u(numbers.n),
        "e": _b64u(numbers.e),
    }


@dataclass
class KeyRing:
    algorithm: str = "HS256"
    hs_key: str = ""
    rsa_current: _RsaKey | None = None
    rsa_previous: _RsaKey | None = None
    _kid_index: dict[str, _RsaKey] = field(default_factory=dict)

    @classmethod
    def hs256(cls, key: str) -> KeyRing:
        return cls(algorithm="HS256", hs_key=key)

    @classmethod
    def rs256(
        cls,
        private_pem: str | None = None,
        public_keys_pem: str | None = None,
    ) -> KeyRing:
        kid = "kid-" + secrets.token_hex(4)
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
            rk = _RsaKey(
                kid=kid, private_pem=private_pem, public_pem=public_pem, created_at=time.time()
            )
        else:
            rk = _generate_rsa_pair(kid)
        ring = cls(algorithm="RS256", rsa_current=rk)
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
                ekid = "kid-ext-" + secrets.token_hex(4)
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
        if self.algorithm == "HS256":
            return self.hs_key
        if kid and kid in self._kid_index:
            return self._kid_index[kid].public_pem
        if self.rsa_current:
            return self.rsa_current.public_pem
        return self.hs_key

    def rotate(self) -> str | None:
        if self.algorithm != "RS256" or not self.rsa_current:
            return None
        new_kid = "kid-" + secrets.token_hex(4)
        new_key = _generate_rsa_pair(new_kid)
        self.rsa_previous = self.rsa_current
        self.rsa_current = new_key
        self._kid_index[new_key.kid] = new_key
        logger.info("KeyRing: rotated kid new=%s prev=%s", new_kid, self.rsa_previous.kid)
        return new_kid

    def prune(self) -> int:
        if not self.rsa_previous:
            return 0
        if time.time() - self.rsa_previous.created_at > GRACE_SECONDS:
            self._kid_index.pop(self.rsa_previous.kid, None)
            logger.info("KeyRing: pruned expired kid=%s", self.rsa_previous.kid)
            self.rsa_previous = None
            return 1
        return 0

    def jwks(self) -> dict[str, Any]:
        keys: list[dict[str, Any]] = []
        if self.rsa_current:
            keys.append(_rsa_public_jwk(self.rsa_current.kid, self.rsa_current.public_pem))
        if self.rsa_previous:
            keys.append(_rsa_public_jwk(self.rsa_previous.kid, self.rsa_previous.public_pem))
        return {"keys": keys}
