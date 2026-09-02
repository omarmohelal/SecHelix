# SecHelix enterprise readiness

**Date:** 2026-09-01 · **Assessment:** suitable for **evaluation and internal pilots**; not yet
suitable for procurement as a measured security control.

This is written for a security lead deciding whether their team can use SecHelix, and what they
would be signing up for.

---

## 1. Short answer

**You can adopt it today as a review methodology.** It is Apache-2.0, runs entirely inside your own
coding agent, contacts no SecHelix service, stores nothing externally, and produces a machine-
checkable report your CI can gate on.

**You cannot yet justify it on measured accuracy**, because no accuracy has been measured. If your
procurement process requires a published detection rate or false-positive rate, SecHelix does not
meet that bar today and says so.

---

## 2. What is genuinely ready

**Contract-first outputs.** Fifteen versioned JSON Schema contracts. The canonical report validates
against `report-v1`, and as of this pass the gate, the renderer, and the derived Markdown / SARIF /
HTML / redacted outputs all speak that same contract. SARIF 2.1.0 means findings land in existing
code-scanning dashboards.

**A release gate that fails closed.** `scripts/security_gate.py` applies an explicit policy pack and
returns `0` for PASS / PASS_WITH_KNOWN_RISK, `1` for BLOCKED, `2` for INCOMPLETE or malformed input.
As of this pass it **refuses to gate a report that violates the contract** rather than scoring it —
previously a malformed report could return PASS. Unknown integrity-critical coverage cannot silently
become a green check.

**Explicit policy, not vendor opinion.** `policies/default.json` and `policies/strict.json` are
plain JSON: blocking severities, verification requirements, regression requirements, accepted-risk
fields and expiry, forbidden deployment states. Organizations layer their own pack. Guidance for
keeping private policy out of public artifacts is in `docs/private-policy-packs.md`.

**Safety posture.** Adapters normalize scanner output and never execute scans. Gold packs declare
`destructive_actions: false` and `production_mutation: false` as schema constants. The methodology
requires authorization before active testing and moves proof to LOCAL or STAGING when a production
test could mutate money, identity, inventory, or customer data.

**Data handling.** Nothing leaves your environment. The website Workbench parses uploaded reports
in the browser and uploads nothing. Redaction is built into the renderer and the explorer.

**Rights-aware knowledge.** Every knowledge source carries a trust tier and a seven-flag
`allowed_uses` matrix. No source permits full-text storage, embeddings, or model training. Three
curriculum sources are `HUMAN_ONLY` and validators enforce that lesson cards cannot ingest them.

---

## 3. What is not ready

| Gap | Consequence for adoption |
| --- | --- |
| **Full-workflow benchmark `NOT_MEASURED`** | One blind label-suite run is published; no end-to-end workflow claim can be made from it. |
| **One case study, private target** | No public, third-party-verifiable result exists. |
| **Trophy case empty** | No independently confirmed disclosure to point at. |
| **Pre-1.0 (`3.0.0-alpha.4`)** | Contracts may change; treat schema versions as moving. |
| **No signing** | `docs/signed-evidence-bundles.md` is design only. Evidence integrity relies on SHA-256 digests inside the report, not on a signature chain. |
| **No SSO / RBAC / audit retention product** | These are roadmap items, not shipped features. |
| **No hosted runner** | Every run happens in your agent, on your machine or CI. |
| **Human-in-the-loop required** | Severity is a judgement; the workflow assumes a reviewer. |

---

## 4. Verified integration paths

Only Codex is recorded as cold-install verified. Every other environment is documented or
model-compatible, and `COMPATIBILITY.md` keeps those statuses distinct rather than flattening them
into a row of checkmarks. Verify your own host's loader before claiming native support internally.

Install:

```bash
npx skills@latest add omarmohelal/SecHelix --skill sechelix
```

CI usage is documented in `docs/ci-integration.md`; treat scanner artifacts as untrusted input,
generate the canonical report, then run the gate.

---

## 5. A recommended pilot

1. **Pick one authorized repository** and one lane — authorization review is the highest-signal
   starting point.
2. **Run STATIC first.** Record the scope, the attack surface, and the applicability decisions.
   Resist the urge to jump to active testing.
3. **Judge it on the refutations, not the findings.** The evidence in this repository is that
   verification killed a plausible high-severity XSS claim. That behavior — rejecting a finding a
   scanner would have shipped — is the thing worth evaluating.
4. **Gate a non-blocking pipeline** on `security_gate.py` with `policies/default.json` and watch
   what it marks INCOMPLETE. Fail-closed behavior on unknowns is the point.
5. **Keep your own scorecard.** Record candidates, verified findings, refuted candidates, and time
   spent. That is your measurement, and it is the only one that currently exists for your codebase.

---

## 6. Questions a security lead should ask, answered honestly

**"Does it phone home?"** No. There is no SecHelix service. The website is static and the Workbench
parses reports client-side.

**"Can it break production?"** The methodology forbids destructive testing and requires explicit
authorization for anything that could mutate production state. But it runs inside an agent with
whatever permissions you grant it — scope the agent, do not rely on the skill alone.

**"What stops it inventing findings?"** The evidence chain and the independent verification pass. A
`VERIFIED` finding must have all seven chain links established, and the schema validator enforces
that. A verified High or Critical additionally requires an independent verifier and non-empty
verification evidence.

**"How do we know it works?"** Today: you do not, beyond one published case study and a fixture
suite a keyword matcher cannot solve. That is the honest answer, and it is why the benchmark page
says `NOT_MEASURED` instead of showing a number for anything the blind label run did not measure.
