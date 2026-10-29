from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
START_SH = REPO_ROOT / "start.sh"

# Required fail-closed env (start.sh refuses before reaching any subcommand).
_BASE_ENV = {
    "FUSION_IDENTITY_JWT_KEY": "x" * 48,
    "FUSION_IDENTITY_SERVICE_TOKEN": "y" * 32,
    "FUSION_IDENTITY_KEK": "z" * 48,
    "FUSION_IDENTITY_PID_FILE": "",
    "FUSION_IDENTITY_LOG_FILE": "",
}


def _run_registry_check(
    registry: str, port: str, extra: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(_BASE_ENV)
    env["FUSION_REGISTRY"] = registry
    env["FUSION_IDENTITY_PORT"] = port
    env.pop("FUSION_SKIP_REGISTRY_CHECK", None)
    if extra:
        env.update(extra)
    return subprocess.run(
        ["bash", str(START_SH), "registry-check"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )


@pytest.fixture()
def registry_file(tmp_path: Path) -> Path:
    path = tmp_path / "port-registry.yaml"
    path.write_text(
        "services:\n"
        "  fusion-identity:\n"
        "    port: 11470\n"
        "    purpose: test stub\n"
        "  fusion-mlx:\n"
        "    port: 11434\n"
        "    purpose: test stub\n",
        encoding="utf-8",
    )
    return path


def test_registry_check_passes_when_port_registered(registry_file: Path):
    # Issue #23 acceptance: with the entry present the check passes.
    result = _run_registry_check(str(registry_file), "11470")
    assert result.returncode == 0, result.stderr
    assert "registry self-check ok" in result.stdout


def test_registry_check_refuses_on_unregistered_port(registry_file: Path, tmp_path: Path):
    # Issue #23 acceptance: a port missing from the registry refuses to start.
    result = _run_registry_check(str(registry_file), "19999")
    assert result.returncode != 0
    assert "not registered" in result.stdout


def test_registry_check_refuses_when_service_entry_absent(tmp_path: Path):
    # Registry exists but has no fusion-identity entry at all -> refuse.
    other = tmp_path / "other-registry.yaml"
    other.write_text(
        "services:\n  fusion-mlx:\n    port: 11434\n    purpose: test stub\n",
        encoding="utf-8",
    )
    result = _run_registry_check(str(other), "11470")
    assert result.returncode != 0
    assert "not registered" in result.stdout


def test_registry_check_bypass_env(registry_file: Path):
    # Issue #23 acceptance: FUSION_SKIP_REGISTRY_CHECK=1 bypasses the refusal.
    result = _run_registry_check(str(registry_file), "19999", {"FUSION_SKIP_REGISTRY_CHECK": "1"})
    assert result.returncode == 0
    assert "bypassed" in result.stdout


def test_registry_check_missing_file_warns_and_continues(tmp_path: Path):
    # Issue #23 acceptance: missing registry file = warn + continue (standalone deploy).
    result = _run_registry_check(str(tmp_path / "does-not-exist.yaml"), "11470")
    assert result.returncode == 0
    assert "skipped" in result.stdout


def test_registry_check_matches_port_exact(registry_file: Path):
    # A near-miss port (e.g. 1147) must not match the "port: 11470" line.
    result = _run_registry_check(str(registry_file), "1147")
    assert result.returncode != 0
    assert "not registered" in result.stdout
