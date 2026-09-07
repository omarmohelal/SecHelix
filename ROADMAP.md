# SecHelix Roadmap

The roadmap is intentionally short. Shipped work belongs in the [changelog](CHANGELOG.md); evaluation details belong in [docs/EVALUATION.md](docs/EVALUATION.md).

## Current focus

SecHelix already has the core Agent Skill, security-review workflows, evidence contracts, adapters, reports, evaluation fixtures, and an optional local runtime.

The next work should improve **trust, coverage, and usability** rather than add more surface area for its own sake.

## Priorities

### 1. Measure the complete workflow

Run reproducible end-to-end evaluations that exercise the full path:

```text
scope → map → review → verify → fix → regression proof → retest → release gate
```

Publish enough evidence for other people to reproduce or challenge the result.

### 2. Make verification stronger

Improve the independent-verification path so important findings are easier to reproduce, refute, and retest without relying on model confidence alone.

### 3. Improve real-world framework coverage

Deepen practical checks for common web, API, database, cloud, identity, payment, and AI/MCP stacks. Prefer a smaller number of strong, testable workflows over shallow checklist growth.

### 4. Improve change and PR review

Make it easier to review only the security impact of a diff: changed trust boundaries, new data flows, weakened controls, and regression risk.

### 5. Improve team and CI adoption

Keep release-gate behavior predictable, make reports easy to consume in CI, and support private organization policy without forcing companies to fork the public methodology.

### 6. Keep the repository simple

New documentation or features should have a clear user-facing purpose. Avoid duplicate quickstarts, marketing drafts, internal planning notes, vanity metrics, and documentation that repeats another canonical source.

## Non-goals

SecHelix is not trying to become:

- an indiscriminate internet scanner;
- a vulnerability-count leaderboard;
- a replacement for professional security judgment;
- a system that reports scanner/model suspicion as proof;
- a repository that grows complexity just to look more complete.

For shipped changes, use [CHANGELOG.md](CHANGELOG.md). For contributing priorities, see [CONTRIBUTING.md](CONTRIBUTING.md).
