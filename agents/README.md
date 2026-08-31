# SecHelix specialist mesh

SecHelix can run as one agent or as a coordinated review mesh. Parallelism is useful only when review lanes have clear ownership and a coordinator independently verifies claims before integration.

## Roles

| Role | Primary job |
|---|---|
| Surface Mapper | architecture, entrypoints, assets, identities, trust boundaries |
| Auth/AuthZ Reviewer | sessions, roles, BOLA/BFLA, object/tenant/seller ownership |
| Input/Web Reviewer | injection, SSRF, files, browser boundaries, CSP/XSS/redirects |
| Business Logic Reviewer | refunds, entitlements, inventory, workflow abuse, partial success |
| Race/Exact-Once Reviewer | retries, duplicate callbacks, process crash, TOCTOU, outcome unknown |
| Money Reviewer | cost, payout, settlement, refund, margin, currency, accounting invariants |
| Supply Chain Reviewer | dependencies, CI, actions, artifacts, build/release provenance |
| AI/MCP Reviewer | prompt/tool boundaries, tool authorization, agent identity, stored instruction risk |
| Runtime/Browser Reviewer | browser-only/build-only defects and real role/workflow proof |
| Independent Verifier | tries to refute candidate High/Critical findings |

## Coordinator rules

- A review lane may produce candidate findings, never final truth.
- The coordinator deduplicates by root cause.
- High/Critical candidates go to the independent verifier.
- Fix agents should be isolated from review agents where possible.
- Do not run multiple heavy repository-wide suites concurrently on a constrained runner.
- Never let multiple agents mutate the same release tree during certification.

## Model diversity

A SecHelix mesh may use different model providers. Diversity is valuable only if roles are separated and evidence is reconstructed independently. Model agreement by itself is not verification.

Suggested assignments:

- large-context model → mapper;
- strong reasoning model → business logic/races;
- fast model → inventories/variant analysis;
- different provider/model → independent verifier.

Track performance through evals rather than branding claims.