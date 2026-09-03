from __future__ import annotations

import os

import pytest

from fusion_identity.config import ConfigError, load_settings
from fusion_identity.crypto import CryptoError, decrypt_secret, encrypt_secret
from fusion_identity.jwks import KeyRing
from fusion_identity.jwt_utils import JwtError, verify_token

_BASE_ENV = {
    "FUSION_IDENTITY_JWT_KEY": "x" * 48,
    "FUSION_IDENTITY_SERVICE_TOKEN": "y" * 32,
    "FUSION_IDENTITY_KEK": "z" * 48,
}


def _set_env(env: dict[str, str]) -> None:
    for k, v in env.items():
        os.environ[k] = v


def _clear_env(keys: tuple[str, ...]) -> None:
    for k in keys:
        os.environ.pop(k, None)


_CONFIG_KEYS = (
    "FUSION_IDENTITY_JWT_KEY",
    "FUSION_IDENTITY_SERVICE_TOKEN",
    "FUSION_IDENTITY_KEK",
    "FUSION_IDENTITY_JWT_ALGORITHM",
    "FUSION_IDENTITY_PORT",
    "FUSION_IDENTITY_JWT_TTL",
)


def test_load_settings_weak_jwt_key_rejected():
    # F9: a JWT key shorter than the minimum must fail-closed at load.
    env = dict(_BASE_ENV)
    env["FUSION_IDENTITY_JWT_KEY"] = "short"
    _set_env(env)
    try:
        with pytest.raises(ConfigError):
            load_settings()
    finally:
        _clear_env(_CONFIG_KEYS)


def test_load_settings_weak_service_token_rejected():
    # F9: a service token shorter than the minimum must fail-closed.
    env = dict(_BASE_ENV)
    env["FUSION_IDENTITY_SERVICE_TOKEN"] = "short"
    _set_env(env)
    try:
        with pytest.raises(ConfigError):
            load_settings()
    finally:
        _clear_env(_CONFIG_KEYS)


def test_load_settings_kek_missing_rejected():
    # F16: KEK must be set explicitly — no default reuse of the JWT key.
    env = dict(_BASE_ENV)
    env.pop("FUSION_IDENTITY_KEK")
    _set_env(env)
    try:
        with pytest.raises(ConfigError):
            load_settings()
    finally:
        _clear_env(_CONFIG_KEYS)


def test_load_settings_kek_equals_jwt_key_rejected():
    # F16: KEK must not equal the JWT signing key.
    env = dict(_BASE_ENV)
    env["FUSION_IDENTITY_KEK"] = env["FUSION_IDENTITY_JWT_KEY"]
    _set_env(env)
    try:
        with pytest.raises(ConfigError):
            load_settings()
    finally:
        _clear_env(_CONFIG_KEYS)


def test_load_settings_bad_jwt_algorithm_rejected():
    # M8: an unknown jwt_algorithm must fail-closed, not silently default.
    env = dict(_BASE_ENV)
    env["FUSION_IDENTITY_JWT_ALGORITHM"] = "HS25"
    _set_env(env)
    try:
        with pytest.raises(ConfigError):
            load_settings()
    finally:
        _clear_env(_CONFIG_KEYS)


def test_load_settings_weak_bootstrap_pass_rejected():
    # C1: a bootstrap admin password shorter than the minimum must fail-closed.
    # The first admin is the only seed for a fresh tenant table; a weak default
    # defeats fail-closed before any app-layer guard runs.
    env = dict(_BASE_ENV)
    env["FUSION_BOOTSTRAP_ADMIN_PASS"] = "adminpass"
    _set_env(env)
    try:
        with pytest.raises(ConfigError):
            load_settings()
    finally:
        _clear_env(_CONFIG_KEYS + ("FUSION_BOOTSTRAP_ADMIN_PASS",))


def test_load_settings_strong_bootstrap_pass_accepted():
    # C1: a sufficiently long bootstrap password loads successfully.
    env = dict(_BASE_ENV)
    env["FUSION_BOOTSTRAP_ADMIN_PASS"] = "strong-rotate-me-12chars"
    _set_env(env)
    try:
        s = load_settings()
        assert s.bootstrap_admin_pass == "strong-rotate-me-12chars"
    finally:
        _clear_env(_CONFIG_KEYS + ("FUSION_BOOTSTRAP_ADMIN_PASS",))


def test_load_settings_non_int_port_rejected():
    # M8: a non-integer int env must raise ConfigError (not bare ValueError).
    env = dict(_BASE_ENV)
    env["FUSION_IDENTITY_PORT"] = "not-a-port"
    _set_env(env)
    try:
        with pytest.raises(ConfigError):
            load_settings()
    finally:
        _clear_env(_CONFIG_KEYS)


def test_load_settings_valid():
    _set_env(_BASE_ENV)
    try:
        s = load_settings()
        assert s.jwt_signing_key == "x" * 48
        assert s.kek == "z" * 48
        assert s.jwt_algorithm == "HS256"
    finally:
        _clear_env(_CONFIG_KEYS)


def test_crypto_hkdf_roundtrip():
    # F16: HKDF-derived KEK still round-trips encrypt/decrypt.
    kek = "operator-kek-material"
    blob = encrypt_secret("super-secret-idp-client-secret", kek)
    assert decrypt_secret(blob, kek) == "super-secret-idp-client-secret"


def test_crypto_decrypt_tampered_raises_cryptoerror():
    # M5: a tampered blob must raise CryptoError, not an uncaught InvalidTag.
    kek = "operator-kek-material"
    blob = encrypt_secret("plaintext", kek)
    import base64

    raw = bytearray(base64.b64decode(blob))
    raw[-1] ^= 0xFF  # flip a ciphertext bit
    tampered = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(CryptoError):
        decrypt_secret(tampered, kek)


def test_crypto_decrypt_wrong_key_raises_cryptoerror():
    # M5: decrypting with the wrong KEK must raise CryptoError.
    blob = encrypt_secret("plaintext", "kek-a")
    with pytest.raises(CryptoError):
        decrypt_secret(blob, "kek-b")


def test_crypto_decrypt_malformed_raises_cryptoerror():
    # M5: a non-base64 / truncated blob must raise CryptoError.
    with pytest.raises(CryptoError):
        decrypt_secret("!!!not-base64!!!", "kek")
    with pytest.raises(CryptoError):
        import base64

        decrypt_secret(base64.b64encode(b"tooshort").decode(), "kek")


def test_jwt_verify_no_algorithms_rejected():
    # M4: verify_token called without explicit algorithms must raise, not
    # silently accept both HS256 and RS256.
    with pytest.raises(JwtError):
        verify_token(
            "any.token.here",
            "key",
            "fusion-identity",
            "fusion-cluster",
        )


def test_keyring_rs256_unknown_kid_rejected():
    # M3: an unknown kid must raise, not fall back to the current key.
    ring = KeyRing.rs256()
    with pytest.raises(JwtError):
        ring.verify_key_for("kid-does-not-exist")


def test_keyring_rs256_missing_kid_rejected():
    # M3: a missing kid on an RS256 ring must raise.
    ring = KeyRing.rs256()
    with pytest.raises(JwtError):
        ring.verify_key_for(None)


def test_keyring_extra_public_deterministic_kid():
    # L13: extra public keys get a deterministic kid from the key, so loading
    # the same PEM twice yields the same kid.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = (
        priv.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    ring = KeyRing.rs256(public_keys_pem=pem)
    kids = [k for k in ring._kid_index if k.startswith("kid-ext-")]
    assert len(kids) == 1
    # Re-loading the same PEM produces the same kid (deterministic).
    ring2 = KeyRing.rs256(public_keys_pem=pem)
    kids2 = [k for k in ring2._kid_index if k.startswith("kid-ext-")]
    assert kids2 == kids


def test_keyring_rotate_keeps_retired_list():
    # L14: rotating twice keeps both retired keys verifiable (no overwrite).
    ring = KeyRing.rs256()
    first_kid = ring.kid
    ring.rotate()
    second_kid = ring.kid
    ring.rotate()
    # All three keys (current + two retired) are in the kid index.
    assert first_kid in ring._kid_index
    assert second_kid in ring._kid_index
    assert ring.kid in ring._kid_index
    # jwks publishes all three within the grace window.
    jwks_kids = [k["kid"] for k in ring.jwks()["keys"]]
    assert first_kid in jwks_kids
    assert second_kid in jwks_kids
    assert ring.kid in jwks_kids
