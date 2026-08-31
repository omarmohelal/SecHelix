# SecHelix methodology

## Principle

SecHelix optimizes for **trusted findings**, not finding count.

A candidate is a hypothesis until it has enough evidence to establish attacker control, reachability, a failed trust boundary, concrete impact, and a safe reproduction. High/Critical candidates receive an independent verification pass.

## Applicability before testing

The catalog is a cross product of security families and verification lenses. That creates broad coverage without implying that every combination belongs on every target.

Each hypothesis must be labeled before testing:

- `APPLICABLE`
- `NOT_APPLICABLE` — include reason
- `UNKNOWN_NEEDS_EVIDENCE`

This prevents meaningless payload spraying and makes coverage auditable.

## Confidence states

- `VERIFIED` — evidence chain is complete enough to act on.
- `LIKELY_BUT_UNPROVEN` — important signal, missing a decisive link.
- `FALSE_POSITIVE` — the suspected path is blocked or assumptions are wrong.
- `DUPLICATE_ROOT_CAUSE` — another verified issue explains the same failure.
- `BLOCKED_BY_ENVIRONMENT` — proof requires unavailable but legitimate environment evidence.

## Severity

Severity combines impact, exploitability, prerequisites, scope, and recoverability. Do not assign Critical simply because a CWE category can be Critical in some systems.

Suggested release semantics:

- Critical — direct compromise of a core trust boundary with severe impact.
- High — serious integrity/confidentiality/financial isolation failure.
- Medium — meaningful but constrained weakness.
- Low — narrow hardening defect with limited impact.
- Info — design/observability improvement, not a vulnerability.

## Independent verification

The verifier should receive the candidate finding as a claim to challenge. It should attempt to disprove:

1. attacker influence;
2. reachability;
3. required role/state assumptions;
4. missing compensating controls;
5. claimed impact;
6. reproducibility;
7. whether the defect is actually a duplicate of another root cause.

Agreement without independent reconstruction is not verification.

## Dynamic testing

Dynamic proof is bounded by scope and environment.

- Local: use fixtures freely if they are isolated and reversible.
- Staging: use allowlisted targets and rollback plans.
- Production-safe: prefer read-only evidence and the smallest non-destructive proof.

Never use destructive behavior simply to make a finding easier to demonstrate.

## Business logic

Treat state machines as security boundaries. For each transition identify:

- preconditions;
- actor;
- source of truth;
- side effects;
- idempotency identity;
- retry behavior;
- terminal behavior;
- partial-success behavior;
- rollback/reconciliation behavior.

This is particularly important for refunds, payouts, fulfillment, inventory, external providers, admin workflows, and multi-tenant assignment.

## Fix quality

Prefer canonical fixes that make the invalid state unrepresentable or fail closed. Add regression proof at the level that catches the real failure: unit, database, integration, browser, or release/build.

A typecheck is not a browser bundle test. A source grep is not an authorization test. A mock is not proof of a database constraint if the vulnerability depends on the constraint.