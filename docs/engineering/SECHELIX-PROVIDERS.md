# SecHelix LLM providers

**Status date:** 2026-10-29

SecHelix routes each reasoning node through a swappable `ProviderExecutor`. The
runner never learns which vendor answered — evidence contracts stay
model-neutral, malformed output fails closed, and unmeasured accounting is
`None`, never `0`.

## Available executors

| Executor | Kind | Selected by | Auth | Status |
|---|---|---|---|---|
| `none` (NullExecutor) | orchestration only | default | — | WORKING |
| `claude-code` | local agent CLI | `--executor claude-code` | Claude Code CLI owns it | present |
| `gemini-cli` | local agent CLI | `--executor gemini-cli` | Gemini CLI owns it | WORKING |
| `openrouter` | HTTP (OpenAI-compatible) | `--executor openrouter` | `SECHELIX_OPENROUTER_API_KEY` | **WORKING — live-verified** |
| `wasm-gateway` | HTTP (OpenAI-compatible) | `--executor wasm-gateway` | `SECHELIX_WASM_API_KEY` | **built; live-unverified** (no key yet) |

## OpenRouter — verified capability matrix

Adapter: `sechelix_runner/providers/openrouter.py` (stdlib `urllib`, fail-closed,
key confined to the `Authorization` header). Probed live on 2026-10-29 with
`scripts/probe_provider.py` against model `qwen/qwen3.8-27b`:

| Capability | Result | Evidence |
|---|---|---|
| Chat completion | **OK** | returns content; `prompt_tokens`/`completion_tokens`/`cost` all measured |
| Token + cost accounting | **OK** | `usage.cost` populated when `{"usage":{"include":true}}` is sent |
| Tool / function calling | **OK** | `get_weather` called with `{"city":"Cairo"}` |
| Streaming (SSE) | **OK** | 118 `data:` chunks + `[DONE]` marker |
| Structured output (JSON mode) | **OK** | `response_format:{type:json_object}` returned valid JSON |
| Error shape | **OK** | bogus model → HTTP 400, `"... is not a valid model ID"` |

Takeaway: `qwen/qwen3.8-27b` supports every feature the routing layer needs
(tool-use orchestration, structured verification output). The same adapter
accepts any OpenRouter model via `--model` or `SECHELIX_OPENROUTER_MODEL`.

### Structured output (schema enforcement)

`ProviderExecutor.invoke` takes an optional `response_schema`. When the reasoner
runs a node it passes that node's schema (`NODE_OUTPUT_SCHEMA`, or
`VERIFIER_OUTPUT_SCHEMA` for the independent verifier). The HTTP providers send it
as `response_format: json_schema` after `strictify()` tightens it to the
OpenAI-strict shape (every field required, `additionalProperties:false`); local
agent CLIs ignore it (they are told the shape in the prompt). This never relaxes
the downstream validator — it only makes a conforming response far more likely.
It is what lets a live model pass the strict verifier contract: without it,
plain-prompt models dropped the bound `candidate_ref` or `refutation_attempt`
and every verify node failed closed.

## wasm gateway (ai.wasmjsvm.com) — built, not yet live-verified

Adapter: `sechelix_runner/providers/wasm_gateway.py`, sharing OpenRouter's
fail-closed parser and key-safety. The request is intentionally **conservative**
— a plain `model` + `messages` chat completion with no OpenRouter-only fields —
because the brief warns the gateway may not implement every OpenAI feature.

Defaults: base `https://ai.wasmjsvm.com/v1`, model `deepseek-v4.1-flash`, key
`SECHELIX_WASM_API_KEY`.

**Blocker:** no key is set, so connectivity and the capability matrix are
**unverified**. Unit tests (request shape + key-safety) pass; the live test
(`tests/runner/test_wasm_gateway_live.py`) skips. To verify, export the key and:

```bash
python scripts/probe_provider.py --key-env SECHELIX_WASM_API_KEY \
    --base https://ai.wasmjsvm.com/v1 --model deepseek-v4.1-flash
python -m pytest -q tests/runner/test_wasm_gateway_live.py -rs
```

Then fill a verified capability matrix here, exactly as OpenRouter's above. Until
then, do not assume tool calling / streaming / JSON mode work on this gateway.

## Configuration

```bash
export SECHELIX_OPENROUTER_API_KEY='sk-or-...'      # required
export SECHELIX_OPENROUTER_MODEL='qwen/qwen3.8-27b' # or any OpenRouter slug
# optional: export SECHELIX_OPENROUTER_BASE_URL='https://openrouter.ai/api/v1'

sechelix doctor                 # shows available_reasoning_executors.openrouter = true
sechelix audit . --executor openrouter --max-cost 0.50 --max-nodes 8
python scripts/probe_provider.py   # re-run the capability probe
```

### WSL note

Ubuntu's `~/.bashrc` returns early for non-interactive shells. Exports appended
there are seen by an **interactive** shell (`bash -ic`) but not a plain
non-interactive `bash -lc`. Put provider exports where the shells that run
SecHelix will read them (interactive login, or `~/.profile`), or pass them
inline to the command.

## Security boundary

- The key is read from the environment, placed only in the request header, and
  never written to `ProviderResult.raw`, an exception message, or a log line
  (asserted by `tests/runner/test_openrouter_provider.py`).
- Prompts carry whatever Evidence block the node built, which may include source
  under review. Selecting an HTTP provider is therefore an explicit decision to
  send that content to that provider; the runner never reroutes to one silently.
- `scripts/probe_provider.py` makes real paid calls and is never run in CI.
