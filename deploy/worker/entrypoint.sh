#!/usr/bin/env bash
# Start the SecHelix pentest worker with server-side ceilings. Everything here
# is an upper bound a submitted config can only tighten. The executor is
# claude-code only when an API key is present, so a missing key degrades to
# bounded discovery instead of crash-looping.
set -euo pipefail

PORT="${PORT:-8787}"
WORKER_ROOT="${WORKER_ROOT:-/data}"
mkdir -p "$WORKER_ROOT"

EXECUTOR="none"
if [ -n "${ANTHROPIC_API_KEY:-}" ] && command -v claude >/dev/null 2>&1; then
  EXECUTOR="claude-code"
fi

args=(
  --bind 0.0.0.0
  --port "$PORT"
  --root "$WORKER_ROOT"
  --executor "$EXECUTOR"
  --concurrency "${WORKER_CONCURRENCY:-1}"
  --max-pages "${WORKER_MAX_PAGES:-25}"
  --max-depth "${WORKER_MAX_DEPTH:-2}"
  --max-seconds "${WORKER_MAX_SECONDS:-1800}"
  --max-nodes "${WORKER_MAX_NODES:-32}"
)
[ -n "${WORKER_MAX_COST:-}" ] && args+=(--max-cost "$WORKER_MAX_COST")
[ -n "${WORKER_MODEL:-}" ] && args+=(--model "$WORKER_MODEL")
# Optional host allowlist for hosted verification: comma-separated.
if [ -n "${WORKER_ALLOW_TARGETS:-}" ]; then
  IFS=',' read -ra allow <<<"$WORKER_ALLOW_TARGETS"
  for host in "${allow[@]}"; do
    host="$(echo "$host" | xargs)"
    [ -n "$host" ] && args+=(--allow-target "$host")
  done
fi

echo "sechelix-worker: executor=${EXECUTOR} port=${PORT} root=${WORKER_ROOT}" >&2
exec sechelix-pentest-worker "${args[@]}"
