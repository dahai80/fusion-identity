#!/usr/bin/env bash
set -euo pipefail

# Regenerate the gRPC Python stubs from fusion_identity/grpc/identity.proto.
# Idempotent: safe to re-run. After generation it patches the relative import
# in identity_pb2_grpc.py to the package-qualified form the service uses.
#
# Usage: ./scripts/gen_proto.sh
# Requires: grpcio-tools (pip install grpcio-tools) in the active venv.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTO_DIR="$ROOT_DIR/fusion_identity/grpc"
PROTO="$PROTO_DIR/identity.proto"

if [ ! -f "$PROTO" ]; then
    echo "ERROR: proto not found at $PROTO" >&2
    exit 1
fi

if ! python -c "import grpc_tools.protoc" 2>/dev/null; then
    echo "ERROR: grpcio-tools not installed. Run: pip install grpcio-tools" >&2
    exit 1
fi

echo "gen_proto: compiling $PROTO"
python -m grpc_tools.protoc \
    -I "$PROTO_DIR" \
    --python_out="$PROTO_DIR" \
    --grpc_python_out="$PROTO_DIR" \
    "$PROTO"

PB2_GRPC="$PROTO_DIR/identity_pb2_grpc.py"
if [ ! -f "$PB2_GRPC" ]; then
    echo "ERROR: $PB2_GRPC not generated" >&2
    exit 1
fi

# protoc emits `import identity_pb2 as identity__pb2` (relative), which breaks
# at runtime outside the grpc package dir. Rewrite to the package-qualified
# import the rest of the service uses.
if grep -q "^import identity_pb2 as identity__pb2" "$PB2_GRPC"; then
    python - "$PB2_GRPC" <<'PY'
import sys
path = sys.argv[1]
with open(path) as f:
    src = f.read()
patched = src.replace(
    "import identity_pb2 as identity__pb2",
    "from fusion_identity.grpc import identity_pb2 as identity__pb2",
)
with open(path, "w") as f:
    f.write(patched)
PY
    echo "gen_proto: patched import in identity_pb2_grpc.py"
else
    echo "gen_proto: import already package-qualified"
fi

echo "gen_proto: done"
