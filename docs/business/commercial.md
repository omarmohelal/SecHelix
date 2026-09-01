# SecHelix commercial plan

The open repository should be genuinely useful on its own. Monetization should come from **scale, orchestration, enterprise workflow, and services**, not from intentionally weakening the free security methodology.

## Open core

Keep public:

- canonical `SKILL.md` methodology;
- core coverage catalog;
- evidence/verification model;
- standard agent adapters;
- basic validation/release gate scripts;
- public eval fixtures and benchmark methodology;
- static documentation and landing page.

Apache-2.0 is used for the open core to reduce adoption friction for companies.

## Possible paid products

### SecHelix Cloud

A future hosted control plane could provide:

- Claude/Codex/GLM/model-provider orchestration;
- parallel reviewer scheduling;
- repository connectors;
- report history;
- evidence storage;
- SARIF ingestion;
- scanner adapters;
- usage/budget controls;
- organization policy enforcement;
- trend dashboards;
- team workflows.

### SecHelix Enterprise

Potential features:

- SSO/RBAC;
- private policy/check packs;
- audit retention;
- custom severity policy;
- signed reports/evidence bundles;
- private VPC/on-prem runners;
- SLA/support;
- compliance mappings;
- centralized model/provider configuration.

### Services

Before a hosted product exists, the simplest real business is service-based:

- setup and policy tuning;
- application-security reviews using SecHelix;
- false-positive reduction;
- CI/release-gate integration;
- business-logic/race-condition workshops;
- custom check packs for a company's domain.

## Pricing hypothesis — not a current offer

Validate willingness to pay before building billing:

- Free: open skill and local workflow.
- Team: hosted orchestration/reporting per repository or seat.
- Enterprise: private policy packs, SSO, runners, support.
- Services: fixed-scope or retainer security engineering.

Do not publish prices until the product has measurable evals and real design partners.

## Donations

Crypto donations are a useful early funding channel but should not be the only long-term business model. The website supports a configurable crypto donation CTA while leaving wallet addresses unset until the maintainer chooses them.

## Trust before monetization

Company adoption depends on proof. Priorities before a paid launch:

1. reproducible vulnerable/clean fixtures;
2. false-positive benchmark;
3. model-role comparison with the same fixtures;
4. public case studies on owned/demo targets;
5. versioned releases;
6. security policy and responsible disclosure;
7. stable report schema;
8. deterministic validation scripts.
