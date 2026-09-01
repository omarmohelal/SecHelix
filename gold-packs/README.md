# Gold Check Packs

A Gold Check Pack is a reusable **investigation plan** for one security bug
class. It records what to look for, how to look safely, what would refute the
hypothesis, and what a fix has to preserve. It is not a scanner rule, not a
signature, and not a finding.

Packs deepen the existing catalog in [`catalog/checks.json`](../catalog/checks.json).
They do not create a second catalog and they do not add hypothesis IDs of their
own: every pack cites the catalog hypotheses it deepens.

## Claim status

**A pack match is a HYPOTHESIS.** The Variant Hunter classifies a candidate path
as `EXACT`, `VARIANT`, `REFUTED`, or `BLOCKED`; `EXACT` and `VARIANT` are
discovery classifications only. Applicability, evidence, and independent
verification are still required before anything is reported as a finding, and
`verification.independent_required` is `true` in every pack — a pack cannot
waive it.

**No pack claims measured performance.** Every pack in this directory carries
`calibration.measurement_status: "NOT_MEASURED"` with `sample_size: 0`. There is
no precision or recall number here, and none may be added without a reproducible
benchmark run that publishes its inputs, configuration, and outputs.

Packs also default to non-destructive work: `validation.destructive_actions` and
`validation.production_mutation` are `false`, and dynamic steps stay authorized,
local, and bounded.

## The eighteen packs

Packs come in two shapes. **Bug-class packs** are organised around one security
invariant and generalize across stacks. **Framework packs** take the same
contract and instantiate it in one framework's actual mechanisms, so a reviewer
gets that framework's specific failure shapes — and, just as important, that
framework's specific reasons a suspicious-looking path is *not* a finding.

### Bug-class packs

| Pack | Bug class | Anchor invariant |
| --- | --- | --- |
| [`SEC-AI-MCP-AUTHORITY-001`](SEC-AI-MCP-AUTHORITY-001/pack.json) | Untrusted retrieved content reaching privileged tool calls, tool authority allowlists, prompt and data separation, agent identity | Content that entered a run as data can never widen that run's tools, arguments, or credentials |
| [`SEC-API-SURFACE-001`](SEC-API-SURFACE-001/pack.json) | API, GraphQL, WebSocket and RPC surface: generic entry points, mass assignment, batch amplification, per-resolver authorization | Every entry point applies the typed path's authorization, every written field is one the caller may write, and every expanded unit of work is checked individually |
| [`SEC-AUTHZ-IDOR-001`](SEC-AUTHZ-IDOR-001/pack.json) | Object authorization, missing subject boundary | Every protected object access is constrained by the effective subject at a canonical enforcement boundary |
| [`SEC-BROWSER-DOM-001`](SEC-BROWSER-DOM-001/pack.json) | Browser and DOM security: markup and URL sinks, cross-document messaging, framing and sandboxing, content security policy | Content the application did not author never becomes script in its origin, and every cross-document peer is identified exactly before it is trusted |
| [`SEC-FILE-PARSER-001`](SEC-FILE-PARSER-001/pack.json) | Files, uploads, parsers and deserialization: traversal, zip-slip, archive budgets, unsafe decoders | Every write resolves inside the intended root as a whole path component, and every object-constructing decoder is reached only by authenticated bytes |
| [`SEC-IDENTITY-ATO-001`](SEC-IDENTITY-ATO-001/pack.json) | Identity and account takeover: enumeration, reset and recovery flows, factor enrolment, step-up coverage | A recovery or step-up operation mutates the account named by the proof, and every path that completes it requires the same proof |
| [`SEC-INJECTION-DATAFLOW-001`](SEC-INJECTION-DATAFLOW-001/pack.json) | Injection and dataflow: SQL, document-store, command, template and expression sinks, including second-order reuse | Every component of an executed statement is either application-authored or bound as a value the interpreter cannot read as syntax |
| [`SEC-MONEY-INVARIANT-001`](SEC-MONEY-INVARIANT-001/pack.json) | Cumulative money invariants, partial-success accounting, ledger reconciliation | Committed outbound movements never exceed the captured value, and each movement is recorded exactly once |
| [`SEC-RACE-IDEMPOTENCY-001`](SEC-RACE-IDEMPOTENCY-001/pack.json) | Check-then-act on single-use resources, duplicate submission, retry and replay, outcome-unknown states | At most one execution commits the consumption; every repeat converges on that first committed outcome |
| [`SEC-SESSION-TOKEN-001`](SEC-SESSION-TOKEN-001/pack.json) | Sessions, JWT and tokens: fixation, algorithm confusion, revocation propagation, scope and audience | Authority comes only from a token the verifier validated under its own pinned rules, and it ends when the governing record ends |
| [`SEC-SSRF-FETCH-001`](SEC-SSRF-FETCH-001/pack.json) | Server-side fetch destination control: validation-vs-request TOCTOU, redirect revalidation, resolution gaps, metadata endpoints | Every connection, including each redirect hop, terminates at an address that just passed the destination policy |
| [`SEC-TENANT-RLS-001`](SEC-TENANT-RLS-001/pack.json) | Database, tenant and RLS isolation: missing predicates, policy and role bypass, pooled connection state, migration drift | Every statement against a shared table is constrained to one tenant, by its own predicate or by a policy that demonstrably binds the connecting role |

### Framework packs

| Pack | Framework | Anchor invariant |
| --- | --- | --- |
| [`SEC-DJANGO-ORM-CONFIG-001`](SEC-DJANGO-ORM-CONFIG-001/pack.json) | Django | Caller-supplied text is bound as a value and never becomes query structure, caller-supplied keys are mapped through an allowlist before they become lookups, and no development-time setting is in force where the application accepts requests |
| [`SEC-EXPRESS-NODE-001`](SEC-EXPRESS-NODE-001/pack.json) | Express / Node | Every route that needs a guard is registered after that guard on a path the guard matches, and every value the handler takes from the request is constrained in both value and shape before it is used |
| [`SEC-LARAVEL-ELOQUENT-001`](SEC-LARAVEL-ELOQUENT-001/pack.json) | Laravel | Every attribute written is one the caller may set on that model, and every record reached through a route parameter or a query is one the caller may reach, established on the path that reaches it rather than on a sibling path |
| [`SEC-NEXTJS-BOUNDARY-001`](SEC-NEXTJS-BOUNDARY-001/pack.json) | Next.js (App Router) | Every server entry point re-establishes the caller's identity and permission for itself, because rendering a page is not a precondition for reaching the endpoints that page references |
| [`SEC-SPRING-METHOD-001`](SEC-SPRING-METHOD-001/pack.json) | Spring Boot | Every route to a protected operation passes an enforcement point that actually intercepts it, and the check names the caller's relationship to the specific object rather than only the role they hold |
| [`SEC-SUPABASE-RLS-001`](SEC-SUPABASE-RLS-001/pack.json) | Supabase / PostgREST | Every object the data API exposes is constrained by a policy that binds the role the request runs as, evaluated against claims the caller cannot set, and no object in that schema executes with rights other than the caller's |

Framework packs self-select through `applicability.capability_tags`, which name
framework-specific capabilities rather than generic ones, so a Django review does
not pick up the Next.js pack. Where a framework changed a security-relevant
default between versions, the pack names the versions in
`framework_fingerprints[].versions` rather than assuming one of them — and its
`false_positive_filters` say which version-dependent fact has to be read before a
candidate can be reported at all.

The eval corpus in `evals/fixtures` is framework-neutral synthetic code. Framework
packs therefore cite the fixtures that exercise the same invariant, not fixtures
written in that framework; each says so in its own `limitations`.

## Pack layout

One directory per pack, containing a single `pack.json` that satisfies
[`schemas/gold-check-pack-v1.schema.json`](../schemas/gold-check-pack-v1.schema.json)
(22 required keys, `additionalProperties: false`). The sections are:

- `threat_model` and `applicability` — who, what, and when the pack applies;
- `framework_fingerprints` — leads for where to look, never proof;
- `boundary` and `sinks` — the invariant and the operations that can break it;
- `detection_layers` — signals per layer (`MODEL`, `STATIC`, `CONTRACT`, `DATA`,
  `LOCAL_RUNTIME`, `STAGING_SAFE`);
- `validation` — safe, authorized, bounded reproduction steps;
- `false_positive_filters` and `verification` — what refutes the hypothesis and
  what independent verification must produce;
- `root_causes`, `remediation`, `regression` — the defective invariant, the
  canonical fix, and the fixtures that would catch a regression;
- `variant_strategy`, `mappings`, `calibration`, `limitations` — how the pack
  generalizes, what it maps to, what is unmeasured, and what it cannot tell you.

## Adding a pack

1. Choose an ID matching `^SEC-[A-Z][A-Z0-9-]{4,63}$` and set
   `lifecycle: "REFERENCE"`. Higher lifecycle states are assigned by maintainer
   review, not self-declared.
2. Cite only source IDs that exist in
   [`knowledge/source-registry.json`](../knowledge/source-registry.json), only
   hypothesis IDs that exist in [`catalog/checks.json`](../catalog/checks.json),
   and only fixture IDs that exist in the repository's `evals/fixtures`
   directory (not shipped in the portable skill bundle).
3. Keep `calibration` at `NOT_MEASURED` / `0` unless a reproducible benchmark run
   backs the numbers.
4. Write refutation tests a competent reviewer would actually run, and regression
   assertions that fail on the vulnerable variant *and* keep the legitimate
   operation working on the remediated one — otherwise a blanket denial passes as
   a fix.
5. Cover the compensating-control case. The most useful negative is code that
   *looks* vulnerable and is not, because a real control elsewhere holds the
   invariant. `evals/run_evals.py` requires every fixture to carry exactly the
   `vulnerable` and `clean` variants, so these cases are expressed as a **second
   fixture whose `clean` variant is the compensated code**: both variants share
   the alarming surface and differ only in whether the control actually binds.
   Most packs here reference two fixtures for that reason.
6. Validate:

```bash
python scripts/validate_gold_packs.py
python -m unittest tests.test_gold_packs -v
```

The validator ([`scripts/validate_gold_packs.py`](../scripts/validate_gold_packs.py))
checks the schema plus the semantic rules: known provenance, resolvable catalog
and fixture IDs, honest calibration, non-destructive defaults, and mandatory
independent verification.

See [`references/gold-check-packs.md`](../references/gold-check-packs.md) for the
pack and Variant Hunter contracts in full.
