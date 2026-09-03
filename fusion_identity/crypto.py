from __future__ import annotations

import base64
import logging
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

_NONCE_LEN = 12
_KEY_LEN = 32
# F16: domain-separation salt + info so the KEK derivation is bound to this
# service and cannot collide with any other HKDF consumer of the same material.
_KEK_SALT = b"fusion-identity:v1:kek"
_KEK_INFO = b"fusion-identity:aes-256-gcm-kek"


class CryptoError(RuntimeError):
    pass


def _derive_kek(kek_material: str) -> bytes:
    # F16: single sha256(kek) was weak (no salt/iterations, collision-prone).
    # HKDF-SHA256 with a fixed domain-separated salt + info derives a 256-bit
    # AES-GCM key from the operator-provided KEK material.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=_KEK_SALT,
        info=_KEK_INFO,
    ).derive(kek_material.encode())


def encrypt_secret(plaintext: str, kek_material: str) -> str:
    kek = _derive_kek(kek_material)
    aesgcm = AESGCM(kek)
    nonce = os.urandom(_NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    blob = base64.b64encode(nonce + ct).decode()
    logger.debug("encrypt_secret: ok len=%d", len(blob))
    return blob


def _decrypt_with(blob: str, kek_material: str) -> str:
    # inner decrypt against ONE derived key; raises CryptoError on any failure.
    raw = base64.b64decode(blob, validate=True)
    if len(raw) < _NONCE_LEN + 1:
        raise CryptoError("truncated ciphertext blob")
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    kek = _derive_kek(kek_material)
    aesgcm = AESGCM(kek)
    try:
        pt = aesgcm.decrypt(nonce, ct, None).decode()
    except InvalidTag as exc:
        raise CryptoError("ciphertext authentication failed") from exc
    except UnicodeDecodeError as exc:
        raise CryptoError("ciphertext decrypted to non-utf8") from exc
    return pt


def decrypt_secret(blob: str, kek_material: str, prev_kek_material: str | None = None) -> str:
    # M5: an InvalidTag (tampered/corrupt/wrong-key blob) must surface as a
    # domain error, not an uncaught 500 / silent swallow.
    # D2: KEK online rotation dual-window. During a rotation the current KEK
    # encrypts NEW secrets while some at-rest secrets are still encrypted with
    # the PREVIOUS KEK (until the re-encrypt sweep completes). Try the current
    # KEK first; on an auth failure fall back to prev_kek (if configured) so the
    # grace window keeps old secrets readable without a full stop-the-world.
    try:
        pt = _decrypt_with(blob, kek_material)
        logger.debug("decrypt_secret: ok (current kek) len=%d", len(pt))
        return pt
    except CryptoError:
        if not prev_kek_material or prev_kek_material == kek_material:
            logger.error("decrypt_secret: authentication failed (no prev kek window)")
            raise
        try:
            pt = _decrypt_with(blob, prev_kek_material)
        except CryptoError:
            logger.error("decrypt_secret: authentication failed (current + prev kek)")
            raise
        # decrypted with the OLD kek — re-encryption still pending. Log so the
        # operator can see secrets still living in the grace window.
        logger.warning("decrypt_secret: ok (prev kek grace) len=%d — re-encrypt pending", len(pt))
        return pt
    except (ValueError, base64.binascii.Error) as exc:
        logger.error("decrypt_secret: malformed blob (base64)")
        raise CryptoError("malformed ciphertext blob") from exc
