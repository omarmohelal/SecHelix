# Company rollout

SecHelix should enter a company as a **measured review workflow**, not as a magical security certificate.

## Phase 1 — design partner

Choose one service with a known owner and existing test environment.

Baseline:

- architecture and trust boundaries;
- existing security tooling;
- known vulnerabilities/incidents;
- current false-positive burden;
- release process;
- critical business invariants.

Run SecHelix alongside the existing review process, not instead of it.

## Phase 2 — calibrate

Measure:

- candidate findings;
- verified findings;
- rejected false positives;
- issues humans found that SecHelix missed;
- verification time;
- model/tool cost;
- regression tests created.

Tune applicability and company policy before expanding.

## Phase 3 — policy pack

Add a private organization layer describing:

- roles and privilege boundaries;
- tenant/seller/customer isolation rules;
- sensitive assets;
- money/payout/inventory invariants;
- required scanners;
- forbidden deployment states;
- required browser/database proofs;
- severity policy;
- production-safe testing restrictions.

Keep this private pack outside the public SecHelix core.

## Phase 4 — release gate

Use SecHelix as one release input:

- unresolved verified Critical → block;
- unresolved verified High → block unless explicitly accepted by policy;
- blocked evidence on a critical invariant → incomplete, not green;
- scanner-only alert → not automatically blocking until verified unless company policy says otherwise.

## Phase 5 — scale

Only after calibration:

- add more repositories;
- centralize reports;
- add SARIF/scanner adapters;
- add private runners;
- compare model-role performance;
- maintain historical trend/evidence;
- sign release evidence where useful.

## Human ownership

SecHelix does not remove responsibility from security/application owners. Important risk acceptance remains a human organizational decision.

## Success criteria

A mature rollout should show at least one of:

- more important issues found before release;
- fewer false positives reaching engineers;
- shorter verification time;
- stronger regression coverage;
- clearer security ownership/invariants;
- more reliable release evidence.

## VNext operating artifacts

The repository now provides public, generic examples for the operational layer:

- [`../policies/`](../policies/) — default, strict, and example organization gate policy packs;
- [`audit-and-retention.md`](audit-and-retention.md) — append-only audit event and evidence-retention guidance;
- [`private-policy-packs.md`](private-policy-packs.md) — separation and review rules for company-specific policy;
- [`signed-evidence-bundles.md`](signed-evidence-bundles.md) — a design for manifests and signatures, not a claim that signing is already deployed;
- [`ci-integration.md`](ci-integration.md) — fail-closed CI examples and outcome handling.

Public examples contain no real company identities, assets, trust boundaries, or
risk approvals. Copy them into a private repository before adding organization
details. Access to the private pack should be narrower than access to the
application source when it exposes incident history, sensitive architecture, or
accepted-risk rationale.

## Minimum production ownership

A company rollout should name owners for:

1. scope and authorization;
2. policy-pack review;
3. independent verification;
4. risk acceptance and expiration;
5. evidence retention and deletion;
6. release-gate operation;
7. signing identity and verification, if evidence bundles are signed.

Do not let the same unattended model both assert an important finding and
approve its verification or risk acceptance.
