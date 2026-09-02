from __future__ import annotations

import base64
import hashlib
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_NONCE_LEN = 12


def _derive_kek(kek_material: str) -> bytes:
    return hashlib.sha256(kek_material.encode()).digest()


def encrypt_secret(plaintext: str, kek_material: str) -> str:
    kek = _derive_kek(kek_material)
    aesgcm = AESGCM(kek)
    nonce = os.urandom(_NONCE_LEN)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    blob = base64.b64encode(nonce + ct).decode()
    logger.debug("encrypt_secret: ok len=%d", len(blob))
    return blob


def decrypt_secret(blob: str, kek_material: str) -> str:
    raw = base64.b64decode(blob)
    nonce, ct = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    kek = _derive_kek(kek_material)
    aesgcm = AESGCM(kek)
    pt = aesgcm.decrypt(nonce, ct, None).decode()
    logger.debug("decrypt_secret: ok len=%d", len(pt))
    return pt
