# V4: the first run with a real reasoning executor — 2026-09-02

The runner could orchestrate but could not think. This records the first time it
did both, what that cost, and exactly how little the numbers below support.

**This is not a benchmark.** Sample size is 2 candidates on a 10-file toy
corpus. It is an existence proof that the pipeline works end to end, and nothing
more. The blind label suite (`MEASURED`, precision 0.950) is unaffected and is
still the only measured accuracy figure this project has.

## What was run

| | |
|---|---|
| Provider | authenticated Claude Code CLI, non-interactive (`-p --output-format json`) |
| Model reported by the host | `claude-fable-5` |
| Provider reported by the host | `firstParty` |
| Target | `examples/demo-app` — 5 vulnerable files, 5 clean counterparts |
| Executor | `ReasoningExecutor(ClaudeCodeExecutor())` |

## Result 1 — the hunter did not flag the clean pair

The authorization lane received the source of **both** `vulnerable/orders.py`
and `clean/orders.py`, which differ only in the ownership check.

```
HUNTER  SUCCEEDED  137s  cost=$0.4010  output_tokens=8338
candidates: 1
  - [examples/demo-app/vulnerable/orders.py] get_order returns an order looked
    up by id alone and never verifies ownership
```

One candidate, on the vulnerable file. The clean file was not reported.

## Result 2 — the verifier refuted a planted false candidate

The verifier was given two candidates: the real one above, and one **planted**
against `clean/orders.py` carrying deliberately loud conclusion fields
(`confidence: HIGH`, `severity: CRITICAL`, `verdict: exploitable`,
`hunter_notes: certain this is a real IDOR`).

```
VERIFIER SUCCEEDED  78s  cost=$0.8724
input candidates: 2  (1 true, 1 planted false)
survived refutation: 1
  KEPT: examples/demo-app/vulnerable/orders.py — get_order

notes: refuted: the candidate locating the missing-ownership claim at
examples/demo-app/clean/orders.py:get_order is false. The clean variant
explicitly compares order['user_id'] to session['user_id'] and returns
(None, 404) on mismatch before the success return...
```

It kept the true one and refuted the false one, with reasoning that names the
specific line that makes the claim wrong.

## Result 3 — role isolation held against real data

The verifier prompt was captured and searched for the planted conclusion values:

| Value planted on the candidate | Present in verifier evidence |
|---|---|
| `HIGH` | **No** |
| `CRITICAL` | **No** |
| `exploitable` | **No** |
| `certain this is a real IDOR` | **No** |
| `IDOR on /orders/{id}` (observation) | Yes |
| `app.py:42` (observation) | Yes |
| `no owner check` (observation) | Yes |

The verifier reached its refutation without ever being told how convinced the
hunter was. That is the property the whole quorum design exists for, and this is
the first time it has been checked against a live model rather than a fixture.

## Cost, honestly

| Node | Wall clock | Cost |
|---|---|---|
| Mapper (separate run) | 114 s | $1.0175 |
| Authorization hunter | 137 s | $0.4010 |
| Independent verifier | 78 s | $0.8724 |

Roughly **$0.40–$1.02 per node**, dominated by prompt-cache creation. A 12-node
audit of a real repository would plausibly cost **$5–12** and take **20–30
minutes** on this provider. That is a material operating cost and the budget
governor is not decoration.

Three failed attempts before the first success cost a further **~$1.60** and
produced nothing.

## Two defects this run exposed

**`--max-turns 1` was unusable.** The model attempts `Read`/`Grep` against the
files named in its view even when those tools are denied. Each attempt consumes
a turn, so the CLI returned `error_max_turns` with no result — while still
charging for it. Fixed by raising the default to 4 so a denied attempt is
absorbed, and by telling the model in the prompt that it has no tools so the
attempt is not made at all.

**A non-zero exit was discarding the reason and the spend.** The CLI returns a
full envelope on failure naming the cause and `total_cost_usd`. The adapter was
raising on the exit code before parsing it, so a failure reported a truncated
blob and lost money that had genuinely been spent. It now parses first and
reports `provider did not complete (error_max_turns), stop_reason=tool_use;
0.4006 USD already spent`.

**One transient failure is unexplained.** An early verifier invocation returned
`FAILED` in 9 s with no model usage recorded. An immediate probe of the same
provider succeeded, and the identical run succeeded on retry. It is recorded
here because it happened, not because it is understood.

## What this does not establish

- **Not accuracy.** Two candidates. One true positive, one true negative. No
  precision, recall or false-positive rate can be computed from that, and none
  is claimed.
- **Not a comparison.** No competitor was run on this corpus.
- **Not the full workflow.** Remediation, patch verification, regression proof
  and the release gate did not execute. The full SecHelix workflow remains
  `NOT_MEASURED`.
- **Not repeatable-by-default.** The provider is non-deterministic; replay
  reproduces the orchestration, not the model output.

The demo corpus is deliberately small and obvious. It exists so a newcomer can
watch the refutation happen in about three minutes, not so anyone can score it.
