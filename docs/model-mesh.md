# Model-neutral specialist mesh

SecHelix assigns work by measured capability, scope and evidence independence. A model name, provider claim or agreement count is never security evidence.

## Evidence flow

```text
authorized scope
  -> surface map
    -> applicable specialist lanes
      -> CANDIDATE / UNASSESSED packets
        -> coordinator root-cause deduplication
          -> neutral verifier packet
            -> independent refutation/reconstruction
              -> remediation review
                -> regression/release verification
```

The verifier is an evidence boundary, not another vote. It should not inherit a hunter's confidence, desired severity or instruction that the candidate is true.

## Capability-based assignments

| Work unit | Required capability evidence | Useful operating characteristics | Disqualifiers |
|---|---|---|---|
| Surface mapper | route/symbol coverage, correct boundary graph, low invented-node rate | large context, reliable structured extraction | repeatedly invents architecture or misses entrypoints |
| Authentication/authorization | verified precision on role/session fixtures, fail-closed reasoning | precise cross-layer tracing | treats UI hiding or middleware presence as proof |
| Business logic/payments | state-machine accuracy, invalid-transition recall, arithmetic consistency | strong multi-step reasoning | cannot preserve source-of-truth and outcome-unknown distinctions |
| Race/idempotency | reproducible interleaving analysis, low flaky-test attribution | careful temporal reasoning | proposes uncontrolled load as verification |
| Injection/parser | source-to-sink trace precision and safe fixture design | efficient variant analysis | promotes dangerous APIs without attacker-control proof |
| Supply chain/CI/cloud | advisory reachability and effective-identity accuracy | good structured inventory | repeats scanner severity as SecHelix severity |
| Browser/extension | real build/runtime evidence quality | browser/tool competence | substitutes typecheck or source grep for runtime proof |
| AI/MCP/agent | tool-scope and instruction-provenance accuracy | cross-protocol reasoning | equates nondeterminism with exploitability |
| Independent verifier | false-positive rejection, verified precision, complete refutation attempts | preferably independent context/provider/model family | saw hidden fixture truth, proposed verdict or hunter chain-of-thought |
| Remediation/regression | canonical-boundary fix rate and behavioral proof quality | compatibility and test discipline | symptom patches or source-text-only regression claims |

All capability measurements are `NOT_MEASURED` until the VNext eval lab runs reproducible fixtures. Do not fill this table with anecdotal model rankings.

## Assignment record

For each run, record:

```json
{
  "run_id": "string",
  "role": "profile name",
  "agent_host": "string",
  "model_or_provider": "operator-supplied label",
  "selection_basis": "benchmark-id or NOT_MEASURED",
  "scope_slice": ["path or surface"],
  "execution_mode": "STATIC|LOCAL|STAGING|PRODUCTION_SAFE",
  "input_artifacts": ["string"],
  "output_artifacts": ["string"],
  "elapsed_ms": "integer|null",
  "token_cost": "number|null"
}
```

Provider/model labels are operational metadata, not quality claims.

## Independence controls

- Give the verifier the candidate claim, necessary evidence locations, scope and compensating-control hints.
- Withhold proposed truth, desired severity, hidden eval labels and persuasive hunter narrative.
- Require independent navigation/reconstruction from cited source slices.
- Use a different model/provider when practical, but treat role separation and independent evidence as the actual control.
- If the same agent must verify, start a clean context and record the reduced-independence limitation.
- Deduplicate candidates before verification where they obviously share a root cause; let the verifier identify uncertain duplicates.

## Parallel execution

- Partition by paths, boundaries or state machines; do not ask every lane for a repository-wide scan.
- A mapper may fan out read-only work after the scope/graph is stable.
- Heavy scanners and full test suites run centrally or under an explicit resource budget.
- Only one remediation lane owns a file at a time.
- A release verifier works on the integrated revision, not on unmerged lane worktrees.
- New evidence may send a candidate back to the owning specialist; it must not bypass verification.

## Fallbacks and failure states

- If no measured specialist is available, use the best available agent and record `selection_basis: NOT_MEASURED`.
- If required repository/environment evidence is absent, emit an evidence gap or `BLOCKED_BY_ENVIRONMENT`; do not infer safety.
- If a verifier is not independent, report that limitation and do not describe agreement as independent proof.
- If integrity-critical coverage is unknown, the downstream gate must choose `INCOMPLETE` or policy-selected `BLOCKED`, never silent `PASS`.

## Benchmark routing policy

Future evals may assign roles using precision, recall, verified precision, false-positive rate, duplicate-root-cause rate, elapsed time, token cost and scanner contribution. Store raw measurements and fixture versions. Re-evaluate assignments after model, prompt, tool or repository-contract changes; never hardcode “model X is the best hacker.”
