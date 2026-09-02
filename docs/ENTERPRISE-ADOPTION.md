# SecHelix Enterprise Adoption

SecHelix can be used as an open AppSec methodology with private organization policy layered on top. The goal is not to replace existing SAST/SCA/DAST tooling; it coordinates evidence from tools and code/runtime review under one verification standard.

## Recommended rollout

### Phase 1 — baseline one service

Choose one representative repository and run SecHelix in `STATIC`, then `LOCAL` if a safe runtime is available.

Capture:

- attack surface and trust boundaries;
- role × object × action matrix;
- applicable/unknown/blocked coverage;
- verified findings and rejected candidates;
- security regression tests;
- release-gate outcome;
- operator time and manual blockers.

Do not gate production on the first experimental run.

### Phase 2 — organization policy pack

Add private requirements without forking the core evidence contract:

- mandatory authentication/session controls;
- tenant-isolation invariants;
- company-specific sensitive-data rules;
- payment/accounting invariants;
- approved/forbidden dependencies or providers;
- cloud/IAM expectations;
- required log/audit events;
- production-safe test restrictions;
- escalation and risk-acceptance owners.

### Phase 3 — CI and pull requests

Use SecHelix as an evidence-aware security review layer around existing CI.

Recommended CI policy:

- verified Critical/High security regressions block release;
- malformed/missing required evidence fails closed to `INCOMPLETE`;
- `UNKNOWN` and `BLOCKED` remain visible and cannot silently become `NOT_APPLICABLE`;
- accepted risk requires an owner, reason, and expiry/review date;
- security fixes require regression proof where practical.

### Phase 4 — measurement

Track useful operational metrics rather than raw finding counts:

- verified precision;
- false-positive rejection rate;
- detection recall on known-ground-truth fixtures;
- time to verification;
- time to root-cause fix;
- regression-proof rate;
- percentage of attack surface classified versus unknown/blocked;
- recurrence rate of previously fixed vulnerability classes.

See `docs/EVALUATION.md` for definitions.

## Integration points

SecHelix can normalize evidence from:

- Semgrep;
- CodeQL/SARIF;
- OSV and package audits;
- Gitleaks;
- Trivy;
- browser/Playwright evidence;
- OWASP ZAP;
- safe Nuclei templates;
- custom organization scanners and test harnesses.

The adapter is not the authority. The canonical finding must still establish attacker control, reachability, boundary failure, impact, root cause, and regression/retest evidence.

## Roles

A mature deployment normally separates:

- **Mapper** — architecture and trust boundaries;
- **Specialists** — authz, authn, business logic, injection, supply chain, cloud, AI/MCP, etc.;
- **Runtime verifier** — evidence from browser/API/DB/test environments;
- **Independent verifier** — tries to disprove important candidates;
- **Owner/release authority** — accepts risk and release decisions.

Do not let model reputation replace independent evidence.

## Production safety

Production dynamic testing must be bounded and non-destructive. Money, inventory, user identity, external provider side effects, customer data, deletion, resource exhaustion, or irreversible actions belong in local/staging fixtures unless a separately approved production procedure exists.

## Procurement / security review questions

Teams evaluating SecHelix should ask:

1. Can we inspect and version the full methodology? Yes — the core is open source.
2. Are unsupported scanner/model claims reported as confirmed vulnerabilities? They should not be.
3. Can we retain private policy and evidence? Organization-specific policy can remain private.
4. Can it coexist with existing scanners? Yes; adapters normalize evidence rather than requiring replacement.
5. Does it claim measured accuracy? One reproducible blind label-suite run is published; full-workflow accuracy is still `NOT_MEASURED`.
6. Can it make fail-closed release decisions? The repository defines `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, and `INCOMPLETE`.
7. Is third-party active testing automatically authorized? No. Scope and authorization are explicit prerequisites.

## Suggested pilot success criteria

A pilot is useful if it demonstrates at least one of these with evidence:

- catches a real boundary failure missed by existing review;
- rejects a meaningful false positive that existing automation escalated;
- finds sibling variants after one root cause;
- converts a recurring vulnerability class into a regression test/policy;
- produces a clearer release decision than disconnected scanner outputs.

Avoid adopting SecHelix because of a large catalog number alone. Adopt it when the evidence workflow improves security decisions.
