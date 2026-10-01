#!/usr/bin/env bash
# Start the SecHelix pentest worker with server-side ceilings. Everything here
# is an upper bound a submitted config can only tighten.
#
# The reasoning executor is claude-code when a Claude credential is present. A
# Claude subscription token (CLAUDE_CODE_OAUTH_TOKEN, from `claude setup-token`)
# is preferred so runs draw on the subscription, not per-token API billing;
# because Claude Code lets ANTHROPIC_API_KEY override the OAuth token, the API
# key is unset when the subscription token is present. The chosen credential is
# forwarded into the run's minimized environment with --pass-env, since nothing
# reaches a run's child process unless it is passed explicitly. With no Claude
# credential the executor is "none" (bounded discovery, findings INCOMPLETE).
set -euo pipefail

PORT="${PORT:-8787}"
WORKER_ROOT="${WORKER_ROOT:-/data}"
mkdir -p "$WORKER_ROOT"

EXECUTOR="none"
CRED="none"
provider_pass=()
if command -v claude >/dev/null 2>&1; then
  if [ -n "${ANTHROPIC_BASE_URL:-}" ] && { [ -n "${ANTHROPIC_AUTH_TOKEN:-}" ] || [ -n "${ANTHROPIC_API_KEY:-}" ]; }; then
    # Gateway mode: any Anthropic-compatible provider (e.g. Z.ai GLM, Kimi),
    # using that provider's own base URL and token. The provider is chosen
    # entirely by the operator's ANTHROPIC_BASE_URL.
    EXECUTOR="claude-code"; CRED="gateway"
    provider_pass+=(--pass-env ANTHROPIC_BASE_URL)
    [ -n "${ANTHROPIC_AUTH_TOKEN:-}" ] && provider_pass+=(--pass-env ANTHROPIC_AUTH_TOKEN)
    [ -n "${ANTHROPIC_API_KEY:-}" ] && provider_pass+=(--pass-env ANTHROPIC_API_KEY)
  elif [ -n "${CLAUDE_CODE_OAUTH_TOKEN:-}" ]; then
    # Subscription: prefer it over the API key, which Claude Code would
    # otherwise let override the token.
    unset ANTHROPIC_API_KEY
    EXECUTOR="claude-code"; CRED="subscription-oauth"
    provider_pass+=(--pass-env CLAUDE_CODE_OAUTH_TOKEN)
  elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    EXECUTOR="claude-code"; CRED="api-key"
    provider_pass+=(--pass-env ANTHROPIC_API_KEY)
  fi
fi
# Let the operator name gateway model ids (e.g. glm-4.6) via the standard
# Claude Code variables, forwarded only when set.
[ -n "${ANTHROPIC_MODEL:-}" ] && provider_pass+=(--pass-env ANTHROPIC_MODEL)
[ -n "${ANTHROPIC_SMALL_FAST_MODEL:-}" ] && provider_pass+=(--pass-env ANTHROPIC_SMALL_FAST_MODEL)
# Forward the container browser flag into each run's minimized environment.
[ -n "${SECHELIX_BROWSER_NO_SANDBOX:-}" ] && provider_pass+=(--pass-env SECHELIX_BROWSER_NO_SANDBOX)
# Playwright finds the image's bundled Chromium through this path; the run's
# minimized child environment must carry it or the browser cannot launch.
[ -n "${PLAYWRIGHT_BROWSERS_PATH:-}" ] && provider_pass+=(--pass-env PLAYWRIGHT_BROWSERS_PATH)

args=(
  --bind "${WORKER_BIND:-::}"
  --port "$PORT"
  --root "$WORKER_ROOT"
  --executor "$EXECUTOR"
  --concurrency "${WORKER_CONCURRENCY:-1}"
  --max-queued-jobs "${WORKER_MAX_QUEUED_JOBS:-32}"
  --max-pages "${WORKER_MAX_PAGES:-25}"
  --max-depth "${WORKER_MAX_DEPTH:-2}"
  --max-seconds "${WORKER_MAX_SECONDS:-1800}"
  --max-nodes "${WORKER_MAX_NODES:-32}"
  "${provider_pass[@]}"
)
[ -n "${WORKER_MAX_COST:-}" ] && args+=(--max-cost "$WORKER_MAX_COST")
[ -n "${WORKER_MODEL:-}" ] && args+=(--model "$WORKER_MODEL")
# Strix is intentionally not bundled in the stock Railway image because it
# requires its own Docker sandbox runtime. A derived/self-hosted worker may
# opt in; sechelix-pentest-worker then verifies both strix and Docker before
# advertising the capability or accepting Strix jobs.
[ "${WORKER_ENABLE_STRIX:-0}" = "1" ] && args+=(--enable-strix)
[ -n "${WORKER_STRIX_TIMEOUT:-}" ] && args+=(--strix-timeout "$WORKER_STRIX_TIMEOUT")
[ -n "${WORKER_STRIX_SCAN_MODE:-}" ] && args+=(--strix-scan-mode "$WORKER_STRIX_SCAN_MODE")
[ -n "${WORKER_STRIX_MAX_TURNS:-}" ] && args+=(--strix-max-turns "$WORKER_STRIX_MAX_TURNS")
[ -n "${WORKER_STRIX_MAX_BUDGET:-}" ] && args+=(--strix-max-budget "$WORKER_STRIX_MAX_BUDGET")
# Optional host allowlist for hosted verification: comma-separated.
if [ -n "${WORKER_ALLOW_TARGETS:-}" ]; then
  IFS=',' read -ra allow <<<"$WORKER_ALLOW_TARGETS"
  for host in "${allow[@]}"; do
    host="$(echo "$host" | xargs)"
    [ -n "$host" ] && args+=(--allow-target "$host")
  done
fi
# Grey-box source checkout. Zero-config by default: a well-formed owner/repo is
# cloned from github.com using a short-lived token the console uploads to the
# in-memory secret store, so nothing here is required. The variables below are
# optional overrides for enterprise/self-hosted git or to lock cloning down.
#   WORKER_CLONE_HOSTS       comma-separated extra trusted hosts (github.com is
#                            already trusted unless WORKER_CLONE_NO_DEFAULT_HOST)
#   WORKER_CLONE_NO_DEFAULT_HOST=1  stop trusting github.com by default
#   WORKER_CLONE_SOURCES     comma-separated REPOSITORY=URL explicit allowlist
#   WORKER_CLONE_TOKEN_REF   secret name holding the clone token (defaults to
#                            SECHELIX_PENTEST_SOURCE_TOKEN at clone time)
if [ -n "${WORKER_CLONE_HOSTS:-}" ]; then
  IFS=',' read -ra hosts <<<"$WORKER_CLONE_HOSTS"
  for host in "${hosts[@]}"; do
    host="$(echo "$host" | xargs)"
    [ -n "$host" ] && args+=(--clone-host "$host")
  done
fi
[ -n "${WORKER_CLONE_NO_DEFAULT_HOST:-}" ] && args+=(--no-default-clone-host)
if [ -n "${WORKER_CLONE_SOURCES:-}" ]; then
  IFS=',' read -ra clones <<<"$WORKER_CLONE_SOURCES"
  for spec in "${clones[@]}"; do
    spec="$(echo "$spec" | xargs)"
    [ -n "$spec" ] && args+=(--clone-source "$spec")
  done
fi
[ -n "${WORKER_CLONE_TOKEN_REF:-}" ] && args+=(--clone-token-ref "$WORKER_CLONE_TOKEN_REF")

echo "sechelix-worker: executor=${EXECUTOR} credential=${CRED} port=${PORT} root=${WORKER_ROOT}" >&2
exec sechelix-pentest-worker "${args[@]}"
