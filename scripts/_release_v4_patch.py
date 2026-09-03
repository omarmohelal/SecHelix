from pathlib import Path

VERSION = "4.0.0-alpha.1"
DATE = "2026-09-03"


def replace(path: str, old: str, new: str) -> None:
    target = Path(path)
    text = target.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"expected text not found in {path}: {old[:100]!r}")
    target.write_text(text.replace(old, new), encoding="utf-8")


# README: release identity and V4 capability surfaces.
replace(
    "README.md",
    '<a href="CHANGELOG.md"><img src="https://img.shields.io/badge/release-3.4.0--alpha.2-9b8cff?style=flat-square" alt="3.4.0 alpha 2"/></a>',
    '<a href="CHANGELOG.md"><img src="https://img.shields.io/badge/release-4.0.0--alpha.1-9b8cff?style=flat-square" alt="4.0.0 alpha 1"/></a>',
)
replace(
    "README.md",
    "| Evidence adapters | Semgrep, CodeQL/SARIF, OSV, Gitleaks, Trivy, npm/pnpm audit, Playwright, ZAP, Nuclei |",
    "| Evidence adapters | Semgrep, **Opengrep**, CodeQL/SARIF, OSV, Gitleaks, Trivy, npm/pnpm audit, Playwright, ZAP, Nuclei |",
)
replace(
    "README.md",
    "| Change review | **Differential security review** — classifies a diff into `NEW_RISK` / `RISK_REDUCED` / `UNCHANGED` / `UNKNOWN` |\n",
    "| Change review | **Differential security review** — classifies a diff into `NEW_RISK` / `RISK_REDUCED` / `UNCHANGED` / `UNKNOWN` |\n"
    "| V4 evidence runtime | **Optional stdlib-only runner `0.1.0`** — deterministic reasoner DAG, least-context routing, budget governor, coverage ledger, replay, loopback API and MCP |\n"
    "| Bounded runtime proof | **LOCAL-only** IDOR, traversal, race/idempotency, webhook and SSRF proof executors; literal loopback only, no ambient proxy/redirect following, and no automatic finding promotion |\n"
    "| Protocol / native lanes | Applicability-gated GraphQL, WebSocket, gRPC, OAuth/OIDC, SAML, JWT, webhook and HTTP proxy/cache review plus candidate-only C/C++/Rust source analysis |\n"
    "| Full-workflow Arena | **Protocol shipped; result still `NOT_MEASURED`** — complete packet coverage, pinned versions, independent assessment and uncontaminated evidence are required before publication |\n",
)
replace(
    "README.md",
    "| Full SecHelix workflow benchmark | **`NOT_MEASURED`** — applicability, independent verification, remediation/regression and release-gate performance have not been measured end to end |",
    "| Full SecHelix workflow benchmark | **`NOT_MEASURED`** — V4 ships the fail-closed Arena protocol, but no uncontaminated end-to-end applicability → verification → remediation/regression → release-gate run has been published |",
)

# Roadmap: make V4 the current shipped milestone without pretending the research backlog is done.
replace(
    "ROADMAP.md",
    "> **Maturity: public alpha (`3.4.0-alpha.2`).**",
    "> **Maturity: public alpha (`4.0.0-alpha.1`).**",
)
replace(
    "ROADMAP.md",
    "## v3.0 alpha — contract-first orchestration foundation — current",
    "## v3.0 alpha — contract-first orchestration foundation — complete",
)
insert_before = "## v3.x — orchestration platform (optional)\n"
v4 = """## v4.0 alpha — optional evidence runtime — current\n\n- **done** — standard-library-only optional runner (`0.1.0`) with deterministic reasoner DAG, least-context views, budget reservations, durable coverage, replay and four report formats;\n- **done** — fail-closed provider isolation with a real Claude Code reasoning adapter and structured-output validation;\n- **done** — loopback API and MCP integration without arbitrary shell exposure;\n- **done** — Docker-backed sandbox specification and real confinement tests: read-only root, dropped capabilities, non-root user, bounded resources, workspace-only writes and default-deny network;\n- **done** — graph-grounded threat modeling plus conservative cross-target false-positive guidance that can ask a future verification question but cannot auto-dismiss a finding;\n- **done** — bounded LOCAL proof execution for IDOR, traversal, race/idempotency, webhook and SSRF. LOCAL HTTP proofs use literal loopback only and never follow redirects or ambient proxies; proof results never self-promote to findings;\n- **done** — deep protocol packs for GraphQL, WebSocket, gRPC, OAuth/OIDC, SAML, JWT, webhooks and HTTP proxy/cache/desync boundaries;\n- **done** — candidate-only native source lane for C, C++ and Rust unsafe/FFI/parser/crypto patterns;\n- **done** — Opengrep interoperability beside the existing deterministic scanner adapters;\n- **done** — production Workbench V4 at `sechelix.com/workbench/v4` for local `run.json` / `graph.json` / `coverage.json` inspection without uploading artifacts;\n- **done** — fail-closed Arena full-workflow measurement protocol with pinned participant versions, explicit capability scope, complete opaque-case coverage, independent assessment and contamination gates;\n- **not measured** — the complete V4 workflow. No end-to-end applicability/verification/remediation/regression/release-gate performance number is published yet;\n- **external blocker** — PyPI upload requires a publishing credential or trusted-publisher configuration outside this repository session;\n- **external evidence needed** — competitor Arena runs and the first public Trophy Case require independently authorized runs, not synthetic claims.\n\n"""
roadmap = Path("ROADMAP.md")
text = roadmap.read_text(encoding="utf-8")
if "## v4.0 alpha — optional evidence runtime — current" not in text:
    if insert_before not in text:
        raise SystemExit("ROADMAP insertion point not found")
    text = text.replace(insert_before, v4 + insert_before)
roadmap.write_text(text, encoding="utf-8")

# Packaging policy: runner version is intentionally independent.
replace(
    "docs/packaging/RELEASE.md",
    "methodology version (`3.4.0-alpha.2`).",
    "methodology version (`4.0.0-alpha.1`).",
)

# Changelog: prepend once.
changelog = Path("CHANGELOG.md")
text = changelog.read_text(encoding="utf-8")
heading = f"## [{VERSION}] - {DATE}\n"
if heading not in text:
    marker = "All notable SecHelix release changes are summarized here. Detailed release notes live in [`docs/releases/`](docs/releases/), and the Git history remains the authoritative development record.\n\n"
    if marker not in text:
        raise SystemExit("CHANGELOG insertion point not found")
    block = f"""## [{VERSION}] - {DATE}\n\n### V4 evidence runtime\n\n- Added the optional standard-library-only runner with deterministic DAG orchestration, least-context routing, budget/coverage state, replayable evidence, loopback API/MCP integration and fail-closed provider execution.\n- Added bounded LOCAL proof execution for authorization/IDOR, traversal, race/idempotency, webhook and SSRF; hardened HTTP proofs to literal loopback with no DNS names, ambient proxies or automatic redirects. Proof behavior never auto-promotes a finding.\n- Added graph-grounded threat modeling, conservative false-positive guidance, deep protocol packs and a candidate-only C/C++/Rust native source lane.\n- Added Opengrep as deterministic candidate evidence.\n\n### Measurement and product surfaces\n\n- Added the fail-closed Arena protocol for end-to-end applicability, verification, false-positive refutation, root-cause, regression-proof and release-gate measurement. The full workflow remains `NOT_MEASURED`; no competitor score is published in this release.\n- Shipped Workbench V4 on `sechelix.com` for local recorded-run inspection without uploading artifacts.\n- Preserved the existing uncontaminated 76-case blind-label result and its explicit boundary: precision 0.950, recall 1.000 and FP rate 0.053 describe the label task, not the complete V4 workflow.\n\n### Distribution\n\n- Bumped the Agent Skill/plugin release to `{VERSION}` while keeping the optional Python runner at its independent `0.1.0` version.\n- Added release notes and automated release/SBOM publication safeguards. PyPI publication remains blocked on an external publishing credential or trusted-publisher setup.\n\nSee [`docs/releases/{VERSION}.md`](docs/releases/{VERSION}.md) for the full notes.\n\n"""
    text = text.replace(marker, marker + block)
changelog.write_text(text, encoding="utf-8")

print("V4 release documentation synchronized")
