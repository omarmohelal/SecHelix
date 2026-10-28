# SecHelix operations — daily commands

**Status date:** 2026-10-29. Every command here was run against this checkout.
Runtime: Python 3.12 in WSL Ubuntu-24.04; the base runner is standard-library
only. Optional live web testing needs the `web` extra (Playwright).

## One-time setup

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e .                 # console scripts: sechelix, sechelix-pentest
sechelix doctor                  # core_contracts must be True
```

Dev/test extras (only to run the test suite):

```bash
pip install pytest
python -m pytest -q              # 1700+ tests, stdlib runner
```

## Health and validation

```bash
sechelix doctor                            # runtime, executors, network mode
sechelix doctor --json                     # same, machine-readable
python scripts/validate_catalog.py         # 21 families x 26 lenses = 546
python scripts/validate_skill.py           # canonical skill + adapter mirrors
# plus validate_distribution / _extensions / _knowledge / _gold_packs
```

## Provider configuration

The reasoning executor is opt-in; the default (`none`) orchestrates without
analysing code. See `SECHELIX-PROVIDERS.md` for the full matrix.

```bash
export SECHELIX_OPENROUTER_API_KEY='sk-or-...'
export SECHELIX_OPENROUTER_MODEL='qwen/qwen3.8-27b'   # any OpenRouter slug
sechelix doctor --json | grep -A4 available_reasoning # openrouter: true

python scripts/probe_provider.py           # live capability probe (paid calls)
```

> WSL note: Ubuntu `~/.bashrc` returns early for non-interactive shells. A plain
> `bash -lc` will **not** see exports appended to `~/.bashrc`; an interactive
> `bash -ic` will. Put provider exports in `~/.profile`, or pass them inline.

## Source-code security review

```bash
# Orchestration only (no model, no cost) -- shows the applicability-selected graph:
sechelix audit path/to/repo --executor none --json

# With a reasoning model, bounded by cost and node count:
sechelix audit path/to/repo --executor openrouter --max-cost 0.50 --max-nodes 8

# A reasoning lane runs only when its required world-context exists; absent lanes
# are recorded as routing decisions, not silent gaps.
```

## Scanner candidates through the independent verifier

Normalize a scanner report, then route its candidates through the verifier --
they are treated as hypotheses to disprove, never trusted because a tool emitted
them:

```bash
python -m adapters.cli osv osv.json        > osv_norm.json   # or semgrep/trivy/...
python -m adapters.cli semgrep semgrep.json > sg_norm.json
sechelix audit path/to/repo --executor openrouter --seed-candidates osv_norm.json
```

Adapters available: `semgrep opengrep codeql sarif osv trivy gitleaks npm-audit
pnpm-audit playwright zap nuclei`. Every record is `CANDIDATE`/`UNASSESSED`; the
tool's severity is kept only as untrusted `tool_signal`.

## Authorized live-web pentest foundation

Scope is deny-by-default and enforced outside the model. Non-loopback targets
require an explicit scope manifest.

```bash
sechelix-pentest plan ...          # plan an engagement
sechelix-pentest init ...          # scope manifest
sechelix-pentest static-scan ...   # static tools
sechelix-pentest crawl ...         # bounded crawl
sechelix-pentest run ...           # execute within scope
```

Modes: `STATIC` (source only), `LOCAL` (loopback fixtures), `STAGING`
(allowlisted hosts), `PRODUCTION_SAFE` (bounded, non-destructive). Never run
destructive payloads, DoS, persistence, or exfiltration.

## Reports and release gate

`sechelix audit --json` emits the full run: coverage, routing, budget/spend,
`verified_findings`, and the release decision. Release outcomes stay within the
SecHelix contract: `PASS` / `PASS_WITH_KNOWN_RISK` / `BLOCKED` / `INCOMPLETE`. An
incomplete assessment never becomes `PASS`.

## Resume / cancel

Budget caps (`--max-cost`, `--max-seconds`, `--max-nodes`) bound every run. The
pentest service supports checkpoints (`sechelix-pentest promotion-checkpoint`);
end-to-end resume/cancel is present but not yet exercised in this baseline.
