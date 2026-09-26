# SecHelix evaluation lab

This lab contains synthetic, non-destructive, paired vulnerable and clean
controls. It measures whether a review pipeline finds important defects while
rejecting clean siblings. No model or scanner is called by the repository.

Current published results: the blind label suite is **MEASURED** —
`results/claude-sonnet-5-blind-2026-09-02.json`, the first uncontaminated run.
The **paired real-CVE measurement** is `results/cve-pairs-2026-09-21.json`: 2 of 12
known defects found under the pre-registered rule, 3 with hand adjudication
(`cve-pairs/README.md`, `docs/research/cve-pairs-2026-09-21.md`).
The **full workflow remains NOT_MEASURED**: `applicability_accuracy`,
`regression_proof_rate` and `release_gate_accuracy` are label-only scoring's
blind spot and keep the literal string, recorded in `results/not-measured.json`.

## Safe workflow

1. Export blind cases without expected labels:

   ```bash
   python evals/run_evals.py --export-cases work/blind-cases.json
   ```

2. Review those cases with an authorized model/scanner pipeline.
3. Supply one prediction for every case using `case_id`, `predicted_label`
   (`VULNERABLE` or `CLEAN`), optional `verification_status`, and optional
   `scanner_sources`.
4. Score only after predictions are fixed:

   ```bash
   python evals/run_evals.py --predictions work/predictions.json --output work/result.json
   ```

The runner reports precision, recall, verified precision, false-positive rate,
duplicate-root-cause rate, time, token cost, model/provider identity, and raw
scanner-source mention counts when supplied. Those mention counts are **not** a
measurement of scanner contribution. Missing operational measurements remain
`NOT_MEASURED`; they are never converted to zero.

## Controlled scanner contribution ablation

`scanner_ablation.py` measures the delta of a declared scanner bundle only when
control and treatment runs use the same blind cases, model, provider, host,
execution mode, prompt reference, fixture-suite version and case digest. The
control arm must declare scanners disabled; the treatment arm declares the
scanner source(s) enabled.

```bash
python evals/scanner_ablation.py \\
  --control work/scanner-control.json \\
  --treatment work/scanner-treatment.json \\
  --output work/scanner-ablation.json
```

Both packets must share an `ablation_run_id` and include `scanner_ablation`
metadata. The output reports deltas for precision, detection recall, verified
precision, false-positive rate, false-positive rejection, and operational
cost/time/token fields when both arms measured them. It also reports aggregate
counts of detections gained/lost and clean false positives removed/introduced.

If multiple scanners are enabled together, the result is explicitly
**bundle-level only**. SecHelix does not assign causal credit to an individual
tool unless that tool is isolated in its own treatment arm. This paired label
ablation is also not a full-workflow Arena score and does not establish
production effectiveness.

## Full-workflow Arena

`arena.py` adds a separate fail-closed protocol for the parts of an AppSec
workflow that vulnerable/clean labels cannot measure: applicability decisions,
independent verification, false-positive refutation, root-cause attribution,
regression proof, and release-gate decisions.

Arena does **not** run competitors and does not declare a winner across unlike
capability scopes. It records exact participant versions, the blind packet
digest, run metadata, contamination state, an independent assessment digest,
and explicit publication blockers. A result remains `NOT_MEASURED` until the
complete blind packet has been assessed exactly once and the blindness and
independence conditions are satisfied.

See [`arena/README.md`](arena/README.md) and start from
[`arena/participants.example.json`](arena/participants.example.json).

Fixtures are synthetic source fragments for static reasoning. Do not deploy
them, attach live credentials, or point them at external targets.


## Dynamic proof primitive benchmark

`dynamic_proof_benchmark.py` executes paired vulnerable/clean LOCAL fixtures for
SecHelix's deterministic proof primitives. It now covers every bounded `ProofClass` currently implemented by the LOCAL
proof executor, with one vulnerable and one clean sibling per class. Coverage
includes authorization/IDOR, race/idempotency, webhook signature/replay, XSS,
SSRF callback, path traversal, CSRF, session revocation, state transition,
payment invariants, workflow sequencing, cross-entity money flow, and
settlement/refund sequencing.

Run it with:

```bash
python evals/dynamic_proof_benchmark.py --sechelix-commit <commit> --output work/dynamic-proof-result.json
```

The artifact records per-case proof class, expected/observed behavior, request
count and elapsed time, plus aggregate case accuracy, vulnerable-behavior
recall, clean-behavior rejection rate, inconclusive rate, and explicit proof
class coverage. CI requires the missing-proof-class list to stay empty.

This is deliberately **not** a full SecHelix benchmark. It does not exercise
candidate discovery, model reasoning, independent verification, remediation,
regression generation, or release-gate decisions. Those remain governed by the
full-workflow Arena protocol and must not inherit scores from this primitive
benchmark.


## Real-browser XSS integration benchmark

`real_browser_xss_benchmark.py` is a separate optional integration benchmark
for the bounded XSS proof. Unlike the deterministic primitive benchmark, it uses
SecHelix's actual `SafeAuthorizedBrowser` / Playwright Chromium backend by
default against a literal-loopback vulnerable/clean fixture pair.

Run it with:

```bash
python evals/real_browser_xss_benchmark.py \
  --sechelix-commit <commit> \
  --output work/real-browser-xss.json
```

If Playwright or Chromium is unavailable, the artifact reports
`BLOCKED_BY_ENVIRONMENT`; it does not convert missing browser infrastructure
into a clean result or a benchmark failure. When the browser is available, both
the executing vulnerable fixture and inert-text clean fixture must classify
correctly for the integration result to be `MEASURED`.

This result kind is `REAL_BROWSER_XSS_INTEGRATION_BENCHMARK`. It measures a
browser-engine integration slice only and must not be presented as full
SecHelix workflow precision/recall, verifier accuracy, remediation quality or
release-gate accuracy.


## Real-browser session integration benchmark

`real_browser_session_benchmark.py` measures the optional Playwright-backed
imported-session path using two isolated browser contexts against a
literal-loopback protected fixture. One context receives a valid ephemeral
fixture session and must observe the operator-defined protected selector; a
separate context receives an invalid session and must not.

```bash
python evals/real_browser_session_benchmark.py \
  --sechelix-commit <commit> \
  --output work/real-browser-session.json
```

Session cookie values are execution-only inputs and never enter the result. The benchmark now also reuses one browser context across a deterministic LOCAL server-side revocation event for paired stale-authority versus immediate-revocation fixtures
artifact. Missing Playwright/Chromium reports `BLOCKED_BY_ENVIRONMENT` rather
than a clean result.

This is an integration measurement for browser context isolation and session
verification. It is separate from the session-revocation proof and is not a
full SecHelix workflow score.
