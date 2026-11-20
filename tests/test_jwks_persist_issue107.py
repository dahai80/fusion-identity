from __future__ import annotations

import json
import logging
import os
import stat

import pytest

from fusion_identity.jwks import KeyRing

logger = logging.getLogger(__name__)


def test_initial_generation_persists_keyring_file(tmp_path) -> None:
    # Issue #107: a freshly generated RS256 key must be persisted IMMEDIATELY
    # (not only on rotation) or the file never appears and every restart
    # rolls a new kid.
    path = str(tmp_path / "jwks-keyring.json")
    ring = KeyRing.rs256(persist_path=path)
    assert os.path.exists(path), "keyring file must exist right after startup"
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"keyring file must be 0600, got {oct(mode)}"
    with open(path) as fh:
        payload = json.load(fh)
    assert payload["algorithm"] == "RS256"
    assert payload["current"]["kid"] == ring.kid
    assert payload["current"]["private_pem"], "private key must be persisted"


def test_restart_serves_same_kid(tmp_path) -> None:
    # Issue #107 acceptance: after a restart the SAME keypair is served
    # (kid stable) — the second rs256() recovers from the persist file.
    path = str(tmp_path / "jwks-keyring.json")
    first = KeyRing.rs256(persist_path=path)
    second = KeyRing.rs256(persist_path=path)
    assert second.kid == first.kid
    assert second.signing_key() == first.signing_key()


def test_rotation_survives_restart(tmp_path) -> None:
    path = str(tmp_path / "jwks-keyring.json")
    ring = KeyRing.rs256(persist_path=path)
    old_kid = ring.kid
    new_kid = ring.rotate()
    assert new_kid != old_kid
    restarted = KeyRing.rs256(persist_path=path)
    assert restarted.kid == new_kid
    # retired key stays verifiable within the grace window across restart
    assert restarted.verify_key_for(old_kid)  # does not raise


def test_persist_failure_refuses_start(tmp_path) -> None:
    # Fail-closed: operator configured FUSION_IDENTITY_JWT_KEYRING_PATH but the
    # write fails (bad dir / perms) — refusing the start beats silently running
    # with a key that is lost (new kid) on the next restart.
    bad_path = str(tmp_path / "no-such-dir" / "jwks-keyring.json")
    with pytest.raises(RuntimeError, match="keyring persist failed"):
        KeyRing.rs256(persist_path=bad_path)


def test_hs256_never_persists(tmp_path) -> None:
    path = str(tmp_path / "jwks-keyring.json")
    KeyRing.hs256("k" * 32)  # no persist_path plumbed for HS256 at all
    ring = KeyRing(algorithm="HS256", hs_key="k" * 32, persist_path=path)
    ring.rotate()  # no-op for HS256
    ring._persist()
    assert not os.path.exists(path)


def test_corrupt_file_falls_back_to_fresh(tmp_path, caplog) -> None:
    path = tmp_path / "jwks-keyring.json"
    path.write_text("{not json")
    with caplog.at_level(logging.WARNING, logger="fusion_identity.jwks"):
        ring = KeyRing.rs256(persist_path=str(path))
    assert ring.kid
    assert any("corrupt persist file" in r.message for r in caplog.records)
