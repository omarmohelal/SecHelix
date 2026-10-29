#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXPECTED_STRIX_COMMIT="007ed1a94e7dbf7b096c81e5b0354533ce94e0db"

python3 - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit(
        "Full SecHelix + Strix requires Python 3.12+ because the pinned "
        "Strix 1.6.2 engine requires Python >=3.12."
    )
print("python:", sys.version.split()[0])
PY

if ! command -v git >/dev/null 2>&1; then
  echo "error: git is required" >&2
  exit 2
fi

git submodule sync --recursive
git submodule update --init --recursive engines/strix

actual="$(git -C engines/strix rev-parse HEAD)"
if [ "$actual" != "$EXPECTED_STRIX_COMMIT" ]; then
  echo "error: engines/strix is not at the SecHelix-tested commit" >&2
  echo "expected: $EXPECTED_STRIX_COMMIT" >&2
  echo "actual:   $actual" >&2
  exit 2
fi

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[web]"
python -m pip install -e ./engines/strix
python -m playwright install chromium

echo
echo "== SecHelix doctor =="
sechelix doctor

echo
echo "== Strix engine contract =="
sechelix-pentest engine-health

echo
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  echo "docker: ready"
else
  echo "warning: Docker is not ready. SecHelix itself is installed, but the"
  echo "embedded Strix engine cannot run until Docker Desktop/Engine is running."
fi

cat <<'EOF'

Full checkout installed.

OpenRouter example:
  export STRIX_LLM="openrouter/z-ai/glm-5.3"
  read -rsp "OpenRouter API key: " LLM_API_KEY; export LLM_API_KEY; echo

Then test an application you own/are authorized to test, for example:
  sechelix-pentest run http://127.0.0.1:3000     --mode local     --source-root /path/to/source     --tool strix     --executor nexus     --strix-scan-mode quick     --strix-max-budget 2
EOF
