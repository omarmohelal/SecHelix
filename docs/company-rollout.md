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