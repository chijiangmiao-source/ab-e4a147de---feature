#!/usr/bin/env bash
# One-shot acceptance for the sparse-Merkle batch verifier image.
#
# Phase 1  IMAGE BUILD CHECK   byte-compile + import every shipped module and
#                             assert the image layout; if a Docker daemon is
#                             reachable (socket mounted) and /src is the build
#                             context, also run a real `docker build`.
# Phase 2  CODE TESTS         unittest suite:
#                             shared-prefix two-key change, tampered sibling
#                             digest, extra proof node (+ all other rejects)
# Phase 3  HTTP SMOKE         real HTTP against TARGET_URL (compose service
#                             "web" when given, otherwise spawns a local server)
#
# Exit code is 0 only when every phase passes.
set -euo pipefail

APP_DIR="${APP_DIR:-/app/app}"
TEST_DIR="${TEST_DIR:-/app/tests}"
SRC_DIR="${SRC_DIR:-/src}"
TARGET_URL="${TARGET_URL:-${1:-}}"
PY="${PYTHON:-python3}"

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
hdr()   { printf '\n==== %s ====\n' "$*"; }

# --------------------------------------------------------------------------- #
hdr "PHASE 1/3: IMAGE BUILD CHECK"
# Running inside the freshly built image: validate the artifact itself.
[ -f "$APP_DIR/server.py" ]      || { red "missing app/server.py in image"; exit 10; }
[ -f "$APP_DIR/smt.py" ]         || { red "missing app/smt.py in image"; exit 10; }
[ -f "$APP_DIR/static/index.html" ] || { red "missing page in image"; exit 10; }
[ -f "$TEST_DIR/test_smt.py" ]   || { red "missing test suite in image"; exit 10; }

"$PY" --version
if ! "$PY" -m compileall -q "$APP_DIR" "$TEST_DIR"; then
  red "byte-compilation failed: image artifact is broken"
  exit 11
fi
"$PY" - "$APP_DIR" <<'PY'
import importlib, sys
sys.path.insert(0, sys.argv[1])
for mod in ("smt", "server"):
    m = importlib.import_module(mod)
    assert hasattr(m, "verify_batch") or mod != "smt"
print("import check ok: smt, server loadable from image")
PY
( cd "$APP_DIR" && "$PY" -c "import server" )

# Optional real image build when a daemon socket is provided (CI / dind).
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && [ -d "$SRC_DIR" ]; then
  echo "Docker daemon reachable: running real image build"
  ( cd "$SRC_DIR" && docker build -t smt-verifier:acceptance . )
else
  echo "(no reachable Docker daemon/context in this run environment; compose "
  echo " 'build: .' itself gates image construction — proceeding with in-image artifact check)"
fi
green "PHASE 1 PASSED"

# --------------------------------------------------------------------------- #
hdr "PHASE 2/3: CODE TESTS (shared-prefix dual key / tampered sibling / extra node / prefix permits)"
"$PY" -m unittest discover -s "$TEST_DIR" -p 'test_*.py' -v
green "PHASE 2 PASSED"

# --------------------------------------------------------------------------- #
hdr "PHASE 3/3: HTTP SMOKE VIA REAL API"
if [ -n "$TARGET_URL" ]; then
  echo "Target: $TARGET_URL"
  "$PY" "$TEST_DIR/http_smoke.py" "$TARGET_URL"
else
  echo "No TARGET_URL given; spawning server inside this container"
  "$PY" "$TEST_DIR/http_smoke.py" --spawn
fi
green "PHASE 3 PASSED"

hdr "ACCEPTANCE PASSED (exit 0)"
exit 0
