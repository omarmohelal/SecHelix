# Runtime trace mode

Static review reads intent. Runtime observation reads behaviour. The interesting bugs live in the
gap between them — a guard that exists in the source and never runs, a redirect that is documented
and not followed, a cookie whose flags are set in one code path and not the one that actually serves
the request.

Runtime trace mode closes that gap in the only direction that is safe. It takes observations the
caller already recorded and asks whether they agree with a static claim. It does not produce the
observations, and it does not verify anything.

## What an observation is

| Kind | What it records |
| --- | --- |
| `HTTP_EXCHANGE` | Request and response *metadata* — method, route, status, timing, header names |
| `API_CALL` | An outbound or internal call, by surface |
| `REDIRECT_CHAIN` | The hops a request actually followed |
| `COOKIE_METADATA` | A cookie's name, flags, domain and path — never its value |
| `WEBSOCKET_HANDSHAKE` | The handshake, not the messages |
| `WEBHOOK_DELIVERY` | A delivery attempt and its outcome |
| `APPLICATION_TRACE` | A selected span from the application's own instrumentation |

Every kind is metadata *about* an exchange. None of them is its content.

## What it refuses to do

| Refusal | Why |
| --- | --- |
| Generate any traffic | It records and correlates. `traffic_capabilities()` inspects the module's own namespace for anything that could put bytes on a wire or start a process, and importing the module fails if it finds one. |
| Default to production | `LOCAL` is the default and `STAGING` is a plain choice. `PRODUCTION_SAFE` is refused unless the restrictions it was chosen under are stated — the same rule `scope-v1` applies to a production scope. |
| Record production safeguards for a trace that was not in production | Recording a restriction that was never in force overstates what was done. |
| Store a cookie value | `cookie_metadata()` has parameters for every flag and none for a value, so a caller holding one has nowhere to put it. A value-shaped signal is dropped by name as well. |
| Store a credential header, a session identifier, or a request body | These have no metadata reading. Redacting them instead would mean betting that a pattern list is complete against arbitrary user content, and that bet is lost quietly. |
| Keep a query-string value | Deciding which parameter is a token is a judgement about a codebase nobody here has read. Parameter *names* are what a surface is matched on; the values are never needed. |
| Verify a finding | A trace can only carry `HYPOTHESIS`, and the contract has no way to express anything else. |
| Report `INSUFFICIENT` as `UNRELATED` | "We saw nothing relevant" and "we could not tell" are different answers, and only one of them is reassuring. |

## Correlation

`correlate(observation, claim)` matches on surface first, then on signals, and returns one of four
strengths.

| Strength | Meaning |
| --- | --- |
| `CONFIRMS` | The surfaces matched and every comparable signal agreed. |
| `CONTRADICTS` | The surfaces matched and at least one comparable signal disagreed. |
| `UNRELATED` | The surfaces were compared and did not correspond. |
| `INSUFFICIENT` | It could not be told. |

The order of those checks is the contract. Anything uncomparable resolves to `INSUFFICIENT` *before*
anything is allowed to conclude `UNRELATED`, because a gap in instrumentation collapsing into
"nothing to see" is how missing coverage becomes reassurance. A correlation is `INSUFFICIENT` when
the observation records no surface, when the claim names none, when the claim predicts no runtime
signal, when nothing it predicts was observed, or when the only comparable signal was redacted —
comparing a placeholder to a real value would manufacture a contradiction out of a safety measure.

Surfaces reach the matcher from three different worlds — a route as the server templated it, a URL
as a client saw it, and a file path as a static reader recorded it — so a claim usually names both
its code location and the route it serves. `{id}`, `:id` and `<int:id>` all match a concrete
segment; a method mismatch is a different surface; a file and a line match at file granularity, and
the match strength says `FILE` rather than pretending the match was exact.

## Redaction

Redaction happens inside `observe()`, so an unredacted `Observation` is never constructed. What
survives goes through [`proof_bundle.redact`](../../sechelix_core/proof_bundle.py) — the same
redaction a proof bundle gets, imported rather than reimplemented, so a pattern added there protects
traces too.

That reuse has one visible cost. `proof_bundle` redacts home-shaped paths, so an observed route
beginning `/home/…` or `/Users/…` loses its surface. The trace does not pretend otherwise: the
observation is flagged `surface_redacted`, and every correlation for it is `INSUFFICIENT`. An
over-redaction becomes an honest "cannot tell" rather than a false "unrelated".

Signal names are dropped component-wise and deliberately bluntly: any name containing `value`,
`token`, `secret`, `password`, `auth`, `credential`, `cookie`, `session`, `sid`, `jwt`, `bearer`,
`key`, `body`, `payload` or `signature` goes, so `session_id` and `api_key_id` are dropped along with
`session` and `api_key`. Cookie facts are dropped too — they belong in a `COOKIE_METADATA`
observation, which has a field for every flag and none for a value. Dropped names are listed on the
observation, so a reader can tell a field that was removed from one that was never observed.

## What a claim gets out of it

A runtime observation records behaviour. A finding claims cause. Observing that a request returned
`200` shows what happened, not why, so runtime agreement alone leaves a claim a `HYPOTHESIS`.

Combined with static evidence and with no contradiction outstanding, `verification_ready` becomes
true. That is a queue, not a promotion: the claim is now worth an independent verifier's time, and
nothing about it has been verified. The contract enforces both halves — `status` is a constant, and
`verification_ready: true` requires static evidence, a confirming observation, and no contradiction.

## Usage

```python
from sechelix_core.runtime_trace import (
    HTTP_EXCHANGE, STAGING, build_trace, claim, cookie_metadata, observe,
)

observations = [
    observe("OBS-1", HTTP_EXCHANGE, surface="GET /api/orders/42",
            signals={"status_code": 200, "authorization": "…"}),   # dropped, not stored
    cookie_metadata("OBS-2", "sid", surface="POST /login",
                    secure=False, http_only=True, same_site="Lax"),
]

claims = [
    claim("SHX-F-1",
          surfaces=["GET /api/orders/{id}", "app/orders.py:41"],
          expected_signals={"status_code": 403},
          evidence_ids=["EV-001"],
          statement="the order lookup omits the tenant predicate"),
]

trace = build_trace("TRACE-DEMO", mode=STAGING, observations=observations, claims=claims)
print(trace["counts"])              # {"CONFIRMS": 0, "CONTRADICTS": 1, ...}
print(trace["assessments"][0]["status"])            # always HYPOTHESIS
print(trace["assessments"][0]["verification_ready"])
```

`build_trace` produces a `runtime-trace-v1` artifact:

```bash
python scripts/validate_contract.py runtime-trace trace.json
```

## What this does not do

- It does not decide whether a finding is real. That is the independent verifier's job, and a trace
  is one input to it.
- It does not instrument anything. Observations come from whatever already records them — a proxy,
  an APM export, a browser session, a webhook log.
- It does not correlate by time. Two things happening in the same second is not a relationship, and
  a correlation this module cannot justify by surface and signal is one it declines to make.
- It does not persist. It is a pure classification over what the caller holds.

## Related

- [`sechelix_core/runtime_trace.py`](../../sechelix_core/runtime_trace.py) — the module
- [`tests/test_runtime_trace.py`](../../tests/test_runtime_trace.py) — the invariants, asserted
- [`schemas/runtime-trace-v1.schema.json`](../../schemas/runtime-trace-v1.schema.json) — the contract
- [Proof bundles](proof-bundles.md) — where the redaction comes from
- [Dependency exploitability](dependency-exploitability.md) — the other place a chain has to be
  established rather than assumed
- [Incremental evidence cache](evidence-cache.md) — why unprovable is treated as invalid
- [Compatibility](compatibility.md)
