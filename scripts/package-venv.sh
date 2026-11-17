#!/usr/bin/env bash
# Build a relocatable venv tarball of fusion-identity for Homebrew install.
#
# The tarball root contains a single `venv/` directory created with
# `python -m venv --copies` (interpreter binary copied in, not symlinked) so
# the only absolute paths left are the ones recorded in pyvenv.cfg and the
# console-script shebangs. The Homebrew formula rewrites those two things at
# install time (see packaging/homebrew/fusion-identity.rb); the smoke test
# here replays the exact same fixup to prove relocation works before upload.
#
# Usage: scripts/package-venv.sh [output-dir]
# Output: fusion-identity-venv-<version>-<os>-<arch>.tar.gz
set -euo pipefail

OUT_DIR="${1:-dist}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3.12}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

command -v "$PY" >/dev/null || {
    echo "error: $PY not found" >&2
    exit 1
}
VERSION="$("$PY" -c "import tomllib; print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])")"
OS="$(uname | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m | sed 's/aarch64/arm64/;s/x86_64/x64/')"
NAME="fusion-identity-venv-${VERSION}-${OS}-${ARCH}"
TARBALL="${OUT_DIR:?}/${NAME}.tar.gz"

echo "package-venv: building ${NAME} in ${WORK}"
"$PY" -m venv --copies "${WORK}/venv"
"${WORK}/venv/bin/pip" install --quiet --no-input --no-cache-dir --upgrade pip
"${WORK}/venv/bin/pip" install --quiet --no-input --no-cache-dir "${REPO_ROOT}"
"${WORK}/venv/bin/pip" install --quiet --no-input --no-cache-dir "${REPO_ROOT}/../fusion-core" 2>/dev/null ||
    "${WORK}/venv/bin/pip" install --quiet --no-input --no-cache-dir "fusion-core>=0.12"

# The console scripts embed the build-time venv python path; drop the stale
# pyc caches (they embed absolute paths too) before packing.
find "${WORK}/venv" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "${WORK}/venv" -type d -name ".mypy_cache" -prune -exec rm -rf {} + 2>/dev/null || true

# Relocation fixup (mirrors the Homebrew formula): Python 3.12 pyvenv.cfg
# has no base-* keys — rewrite `home` (stdlib prefix) and `executable`, and
# repoint script shebangs at the relocated venv python, then prove the entry
# point boots.
PY_BIN="$(command -v "$PY")"
PY_HOME="$(dirname "$PY_BIN")"
fixup_cfg() {
    cfg="$1"
    sed -i.bak \
        -e "s|^home = .*|home = ${PY_HOME}|" \
        -e "s|^executable = .*|executable = ${PY_BIN}|" \
        "$cfg"
    rm -f "${cfg}.bak"
}
cfg="${WORK}/venv/pyvenv.cfg"
fixup_cfg "$cfg"
for script in "${WORK}/venv/bin/"*; do
    [ -f "$script" ] || continue
    head -c 2 "$script" | grep -q "#!" || continue
    sed -i.bak "1s|^#!.*$|#!${WORK}/venv/bin/python|" "$script"
    rm -f "${script}.bak"
done
"${WORK}/venv/bin/fusion-identity" --version

mkdir -p "$OUT_DIR"
tar -czf "$TARBALL" -C "$WORK" venv
echo "package-venv: wrote ${TARBALL} ($(du -h "$TARBALL" | cut -f1))"

# Smoke test the actual artifact: extract elsewhere, re-run the same fixup
# against the final paths, boot the entry point.
SMOKE="$(mktemp -d)"
trap 'rm -rf "$WORK" "$SMOKE"' EXIT
tar -xzf "$TARBALL" -C "$SMOKE"
fixup_cfg "${SMOKE}/venv/pyvenv.cfg"
for script in "${SMOKE}/venv/bin/"*; do
    [ -f "$script" ] || continue
    head -c 2 "$script" | grep -q "#!" || continue
    sed -i.bak "1s|^#!.*$|#!${SMOKE}/venv/bin/python|" "$script"
    rm -f "${script}.bak"
done
GOT="$("${SMOKE}/venv/bin/fusion-identity" --version)"
echo "package-venv: smoke ${GOT}"
[ "$GOT" = "fusion-identity ${VERSION}" ] || {
    echo "error: smoke version mismatch" >&2
    exit 1
}
echo "package-venv: ok"
