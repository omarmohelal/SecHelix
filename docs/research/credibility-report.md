# SecHelix credibility report

<!-- doc-consistency: snapshot -->
> **Dated snapshot.** This is a record of one work session — the before/after numbers below are what was true on the date above; the tree has since moved.

**Date:** 2026-09-01 · **Version at start:** 3.0.0-alpha.4 · **Branch:** `credibility/v3.1-evidence-program`

This report records what was audited, what was found, and what was fixed during a program whose
goal was to close the gap between what SecHelix claims and what it demonstrably does.

The most important findings were in **SecHelix itself**.

---

## 1. Three defects found in SecHelix by auditing it against its own claims

### 1.1 The canonical report contract was fractured — **fixed**

`examples/report.example.json` — the document referenced by `SKILL.md`, `reports/README.md`, the
website Workbench, and every "canonical report" claim — **did not validate against
`schemas/report-v1.schema.json`**. It failed on 20+ constraints: missing `scope_id`, `mode`,
`evidence`, `rejected_false_positives`, `redaction_summary`; lowercase coverage keys; a
`report_id` that did not match the required pattern.

The split ran deeper than the example. `scripts/security_gate.py`, `reports/report_renderer.py`,
and the three shipped policies all consumed a **different, legacy shape**. The published
`report-v1` contract was consumed by exactly one script (`validate_contract.py`).

A product whose headline is "fifteen versioned JSON contracts" cannot have its flagship contract
be the one format its own tools do not speak. This is the kind of defect that ends an evaluation
in the first ten minutes.

**Fixed.** Everything now speaks `report-v1`: schema, example, gate, renderer, derived Markdown /
SARIF / HTML / redacted outputs, and all tests. Two fields were added to the schema because the
operational tooling genuinely needed them and had no contract-legal home:
`coverage.integrity_critical_unknown` (required for the fail-closed integrity rule) and an
optional `deployment_state` (used by the `forbidden_deployment_states` policy knob, which was
until now unreachable for any contract-valid report).

### 1.2 The release gate was fail-**open** — **fixed**

`security_gate.py` scored reports without validating them against the canonical contract. It
returned **`PASS` (exit 0)** for the legacy example that `validate_contract.py` rejected with 20
errors. A malformed report — one whose coverage, evidence links, and finding semantics had never
been checked — could produce a green release decision.

For a product whose central promise is fail-closed behavior, this was the single most damaging
defect in the repository.

**Fixed.** The gate now validates the report against the canonical contract before applying any
policy and refuses to gate a non-conforming document, exiting `2` (`INCOMPLETE`). Verified:

```
$ python scripts/security_gate.py examples/report.example.json --policy policies/default.json
PASS: no unresolved release-blocking conditions          # exit 0

$ python scripts/security_gate.py <report with evidence removed> --policy policies/default.json
INCOMPLETE: report does not satisfy the canonical report contract:
- $: missing required property 'evidence'                # exit 2
```

Two tests now exercise contract enforcement explicitly, one for each direction.

### 1.3 The "blind" evaluation export was not blind — **fixed**

`evals/run_evals.py --export-cases` emitted, for every case:

```json
{"case_id": "EVAL-SSRF-001::vulnerable", "variant": "vulnerable", ...}
```

The ground-truth label appeared **twice** — in the identifier and in a dedicated field. Any model
scored against that export would have been reading the answer key. Every metric the harness could
have produced was meaningless.

**Fixed.** Case identifiers are now opaque deterministic digests (`CASE-017BEFFEE21C2E76`), and the
export discloses no variant, no fixture id, and no rationale. Cases are ordered by digest so
vulnerable/clean pairs are not adjacent. Legacy identifiers still score, so older packets remain
valid. A test asserts that no fixture id and no ground-truth field survives export.

---

## 2. A real audit was performed, and its results are published

Target: `omarmohelal/gamingops-store` at commit `06ab8ca` — a private Next.js storefront,
audited by its owner. STATIC review plus LOCAL runtime reproduction. No scanners enabled, no
external system contacted.

| Outcome | Result |
| --- | --- |
| Candidates raised | 3 |
| **Verified** | **1** (`SHX-F-GOS-HEADERS-001`, MEDIUM) |
| **Refuted** | **2** |
| Fixed | 1 verified + 1 hardening |
| Regression tests added | 10 |
| Release decision | PASS after remediation |

**The verified finding.** The application declared no response security headers at all, so any
origin could frame the storefront. Reproduced locally: a probe page on a different origin embedded
the full interface including the sign-in entry point. Root cause: `next.config.ts` had no
`headers()` policy. After the fix the browser refuses the frame itself —
`Framing '...' violates the following Content Security Policy directive: "frame-ancestors 'none'"`.

**The refuted candidate is the more valuable result.** Remote configuration values reached `href`
and `src` attributes with only whitespace trimming — the exact shape a scanner reports as
high-severity XSS. A local reproduction served a hostile `javascript:` payload; React 19
neutralized it before the DOM. Attacker control was separately not established, since the
configuration source is the operator's own API. Recorded as `FALSE_POSITIVE` with the refutation
retained. The scheme allowlist was still added, labelled as **hardening, not a vulnerability fix**.

Remediation is in `omarmohelal/gamingops-store` PR #2. Evidence artifacts carry SHA-256 digests in
`artifacts/case-studies/gamingops-store-2026-09-01/`.

**No Trophy Case entry was added.** That bar requires a public project and a public fix reference;
this target is private. The rule was applied rather than bent.

### A process finding worth keeping

The first retest appeared to fail — headers still missing, hostile URL still in the DOM. The cause
was a stale Next.js prerender cache plus a still-running server on the old port. Only a clean
rebuild proved the fix. This is recorded because it is precisely how a real fix becomes a false
claim of remediation.

---

## 3. What was strengthened

| Area | Before | After |
| --- | --- | --- |
| Gold Check Packs | 1 | **5** (authz, money, race, SSRF, AI/MCP) |
| Eval fixtures / cases | 8 / 16 | **19 / 38** |
| Fixture case size | 6–13 lines | **38–66 lines**, realistic modules |
| Families covered | 8 | **10** (adds authentication, XSS) |
| Knowledge graph | 5 nodes / 4 edges | **73 nodes / 96 edges** |
| Lesson cards | 1 | **7** |
| Case studies | 0 | **1** |
| Harness validation | none | deterministic baseline, no model required |
| Tests | 76 (20 erroring) | **93 passing** + 19 adapter tests |
| CI validators | gold packs not run | gold-pack validator added |

A packaging bug was also fixed: the portable skill ships gold packs but deliberately not the
evaluation corpus, so **every pack failed validation inside an installed bundle**. The fixture
cross-check now applies only where that corpus exists, with a regression test that runs the real
validator against the actually-shipped tree.

---

## 3b. Claims that were downgraded because they could not be reproduced

A packaging audit ran real cold installs. Only what was actually executed is now marked
`VERIFIED`; two existing claims were **downgraded**, which matters more than the upgrades:

| Claim | Was | Now | Why |
| --- | --- | --- | --- |
| Codex integration | "Cold-install verified" | `DOCUMENTED` | The vendor documents `.agents/skills/`; nobody ran Codex during this audit. |
| `.codex/skills/` mirror | folded into the above | `UNVERIFIED` | It is not a documented Codex discovery path. |
| Portable bundle | "Verified bundle" | `VERIFIED` | Five scripts executed from a cold copy outside the repo. |
| Claude Code plugin | *absent from the matrix* | `VERIFIED` | `claude plugin validate` and `--plugin-dir` load both confirmed. |
| Agent Skills CLI | *absent* | `VERIFIED` | Cold-installed into an empty project. |

A Claude marketplace manifest was **deliberately not added**: with `marketplace.json` present,
`claude plugin validate` stops validating the plugin itself, which is the wrong signal to ship.

Two other honesty fixes: a `skills.sh` badge pointed at a 404 and was removed, and `SECURITY.md`
and `CODE_OF_CONDUCT.md` both routed reports to nowhere and now use GitHub private advisories.

A vocabulary defect in my own work was also corrected: the evaluation fixtures used **19 distinct
family labels for 10 security domains**, which split the per-family metric buckets so a single
domain could score twice. Families are now normalized to 10 canonical values.

---

## 4. What is still not proven

- **No benchmark score exists.** See `SECHELIX-EVALUATION-REPORT.md` for the exact blocker.
- **One case study, one small application** (~600 LOC, no authentication, no server-side state).
  It demonstrates the workflow; it measures nothing general.
- **No third-party has run SecHelix and reported results.** Every artifact here was produced by
  the maintainer or by an assistant working for the maintainer.
- **Severity assignments are judgements**, not CVSS computations.
- **The knowledge graph is curated, not comprehensive** — mappings that could not be confirmed
  against an authoritative catalog were deliberately omitted.
- **One registry entry needs maintainer confirmation**: `owasp-llm-top-10` was added to
  `knowledge/source-registry.json` with conservative rights flags so the AI cluster had a legal
  provenance anchor. Nobody has formally reviewed those terms.

---

## 5. Verification commands

```bash
python -m unittest discover -s tests -p 'test_*.py'      # 93 tests
python -m unittest discover -s adapters/tests            # 19 tests
python scripts/validate_catalog.py
python scripts/validate_skill.py
python scripts/validate_extensions.py
python scripts/validate_knowledge.py
python scripts/validate_gold_packs.py
python scripts/check_no_secrets.py
python scripts/check_local_links.py
python scripts/check_install_snippets.py
python scripts/check_private_site_leakage.py
python scripts/validate_contract.py report examples/report.example.json
python scripts/security_gate.py examples/report.example.json --policy policies/default.json
```

All pass at the time of writing.
