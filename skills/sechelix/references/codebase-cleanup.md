# Codebase Cleanup

Use for an explicitly requested maintainability audit, dead-code investigation or safe cleanup. Be aggressive in investigation and conservative about unsupported deletion. These are quality findings, not vulnerabilities. The security catalog and gate remain unchanged.

## Build the usage map

Record the exact revision and dirty-tree state, workspace/package boundaries, languages, build targets, deployment variants, entrypoints, framework conventions, generated sources, public exports, compatibility contracts and test commands. Cover frontend, backend, workers, scheduled tasks, CLI, migrations and infrastructure. Identify excluded/generated/vendor directories and inaccessible services explicitly.

Read source/configuration before executing repository scripts. Honor the canonical authorized-use and untrusted-repository boundaries. Use the project's existing static tooling where possible; tool output and zero text matches are candidate evidence, not permission to delete. Tool installation must stay within the operator's scope.

## Required review categories

| Category | Investigation | Impact and removal risk |
|---|---|---|
| Dead code | Trace unused functions, variables, imports, files, routes, APIs and dependencies from actual entrypoints. Include package exports, build scripts and production-only imports. | Measure removed maintenance surface and built bytes separately; tree-shaken source removal may save zero runtime bytes. External callers can make apparently unused APIs live. |
| Duplicate logic | Compare behavior, error handling, contracts and ownership across similar implementations. | Consolidate only equivalent semantics. Similar authorization, validation or pricing helpers may intentionally enforce different rules. |
| Unused UI components | Trace routes, layout composition, lazy imports, registries, stories and feature variants. | Removing a component may also remove styles/assets or break an optional route, theme, locale or accessibility state. |
| Excess complexity | Identify duplicated state, unnecessary abstractions, nesting, indirection and repeated transformations. | Prefer a small refactor with observable behavior preserved; shorter code is not automatically clearer or safer. |
| Legacy code | Establish replacement coverage and supported-version/deprecation policy. | Old timestamps are not proof of disuse. Keep compatibility adapters until consumers and rollback requirements are resolved. |
| Redundant DB/API work | Trace repeated queries, N+1 patterns, refetch loops and duplicate requests using call paths and safe traces. | Measure counts/latency if possible. Preserve authorization, tenant scoping, freshness, transaction boundaries, retries, idempotency and side effects before caching/batching. |
| Abandoned/disconnected files | Trace entrypoints, configuration, history and deployment references. | Preserve useful fixtures, legal/license files, runbooks and disaster-recovery tooling even without application imports. Generated mirrors must be fixed at their canonical source. |
| Technical debt | Identify stale configuration, unnecessary dependencies, architecture coupling and maintenance bottlenecks. | Rank by supported value, risk and effort; do not replace working architecture solely to adopt a fashionable library. |

## Deletion evidence standard

For each candidate, attempt to refute the claim of non-use. Check:

- static and dynamic imports, glob loading, reflection, string registries, dependency injection, package entrypoints and side-effect imports;
- file-based routes, framework discovery, templates, CSS selectors, public assets, generated code and code-generation inputs;
- feature flags, environment-specific paths, locales, optional integrations, supported platforms and plugin consumers;
- webhooks, cron, queues, deployment scripts, CI, migrations and externally called API contracts;
- tests, operational documentation, upgrade/downgrade paths and rollback compatibility.

No logs or traffic over a short period does not prove an endpoint is unused. Missing external-consumer evidence means UNKNOWN. Do not delete migrations, persisted data, audit records, authorization checks or supported API contracts as routine dead-code cleanup. Data/schema removal requires a separate evidenced migration plan and the relevant authorization.

Classify candidates as CONFIRMED, UNKNOWN, KEEP or BLOCKED. CONFIRMED means the evidence supports the proposed change within the declared scope, not universal non-use. Keep UNKNOWN/BLOCKED candidates in the backlog and state the evidence needed. No numeric confidence score substitutes for consumer analysis.

## Per-issue report

Use this record for every issue (including refuted candidates):

| Field | Required content |
|---|---|
| ID / category / disposition | Stable ID, one of the eight categories, CONFIRMED/UNKNOWN/KEEP/BLOCKED |
| Location and scope | Exact paths/symbols, revision, affected packages/routes/configurations |
| Evidence and refutation | Commands or traces, caller map, dynamic/external checks and contradictory evidence |
| Why unnecessary | Concrete loss of value, replacement or redundancy; explain why retained candidates still matter |
| Expected impact | Maintenance benefit, estimated files/lines/dependencies/bytes/query count; label estimates vs measured results and avoid double-counting shared bundles |
| Risks | Behavior, callers, security, data, deployment, compatibility and rollback concerns |
| Recommended plan | Keep, delete, consolidate, simplify or deprecate; dependency-ordered steps, effort and priority |
| Verification / rollback | Existing or needed behavioral checks, baseline, exact recovery commit/procedure and any limitations |

## Execution plan

1. Audit and baseline: enumerate scope and categories, collect build/test results and existing failures; create the report and rank high-value low-risk candidates first.
2. Safe removals: when implementation is requested, remove only confirmed unused imports, locals or private modules whose non-use is demonstrated. Update the owning manifest/lockfile with its package manager and check production build paths.
3. Consolidation: preserve behavior and contracts while merging equivalent logic; use focused behavioral regressions for material changes, not tests asserting deleted source strings.
4. Query/API improvements: compare request/query counts and results under equivalent fixtures; verify isolation, freshness and failure/retry behavior. Do not cache personalized results globally.
5. Risky legacy retirement: stage deprecation, caller migration and a rollback window where contracts require it. Leave unsupported deletion blocked rather than guessing.
6. Verify and report: run affected checks plus required repository gates; inspect final diff for accidentally removed guards, fixtures and operational assets. Record actual savings, remaining uncertainty and follow-up work.

Do not mass-delete on an unused-code tool's autofix output. Do not delete tests to manufacture a green suite or rewrite history to hide failures. Reuse existing tests for trivial removals; add tests where a material invariant needs proof. If the request is audit-only, deliver the plan without modifying the target application. Existing explicit implementation/release authorization should be honored without asking again.

## Combined SEO and cleanup ordering

First inventory public routes, exports, assets and indexability. Do not let cleanup delete an orphan page that SEO should internally link, or a rarely called webhook. Fix confirmed defects in small batches. A slug change requires redirects and coordinated link/canonical/sitemap updates. Recheck representative routes and security-sensitive flows after shared component/query refactors. Finish with separate SEO, cleanup and (only if requested) security outcomes.
