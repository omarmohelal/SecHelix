# SecHelix specialist mesh

SecHelix can run as one agent or as a coordinated, model-neutral review mesh. Parallelism is useful only when lanes have explicit ownership and every security claim remains a candidate until the verification boundary.

## Roles

| Profile | Primary ownership |
|---|---|
| `mapper.md` | architecture, identities, assets, entrypoints, data flows, trust boundaries |
| `auth.md` | authentication, sessions, recovery, MFA and federation |
| `authz.md` | object/function authorization, BOLA/BFLA, roles and tenant isolation |
| `injection-web.md` | SQL/command/template/DOM injection, XSS, CSRF, redirects and web controls |
| `ssrf-file-parser.md` | outbound requests, uploads, paths, archives and parser boundaries |
| `business-logic.md` | workflow and state-machine abuse outside payment-specific accounting |
| `payments-accounting.md` | money, refunds, payouts, currencies, ledger and reconciliation invariants |
| `race-idempotency.md` | concurrency, retries, duplicate work, TOCTOU and outcome-unknown handling |
| `database-rls-migrations.md` | database authorization, RLS, constraints, functions and migrations |
| `browser-extension.md` | client/server bundles, DOM, origins and browser-extension boundaries |
| `supply-chain.md` | dependencies, lockfiles, packages, build inputs and provenance |
| `ci-cd-cloud.md` | CI identities, workflows, deployments, cloud policy and runtime configuration |
| `ai-mcp-agent-security.md` | agent identity, prompts, tools, MCP authorization and untrusted context |
| `privacy-logging.md` | data minimization, telemetry, redaction, retention and privacy boundaries |
| `independent-verifier.md` | blind reconstruction and active refutation of candidate findings |
| `remediation-reviewer.md` | canonical root-cause repair and preservation of security/accounting truth |
| `regression-release-verifier.md` | regression proof, neighboring tests and release-readiness evidence |

## Shared candidate contract

Hunting profiles emit JSON-compatible records with these invariants:

- `status` is always `CANDIDATE`;
- `severity` is always `UNASSESSED`;
- tool/model agreement is not verification;
- evidence distinguishes direct observation from inference;
- dynamic proof stays inside the recorded authorized execution mode.

The profile-specific output sections define additional fields. A coordinator may add identifiers or schema metadata but must not silently convert a candidate to a finding.

## Coordinator rules

- Assign disjoint surfaces and require handoffs when a path crosses lane ownership.
- Deduplicate by root cause, not title or scanner rule.
- Give the independent verifier a neutral candidate packet; do not tell it the claim is true.
- High/Critical claims require independent reconstruction before final reporting.
- Keep remediation separate from initial discovery where practical.
- Do not run multiple heavy repository-wide suites concurrently on a constrained runner.
- Never let multiple agents mutate the same release tree during certification.
- Record `NOT_MEASURED` for model capability until reproducible evals exist.

See `docs/model-mesh.md` for capability-based role assignment and evidence-flow rules.
