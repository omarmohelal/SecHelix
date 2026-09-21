# Runtime resources

The workflow in `SKILL.md` never requires code. The installed skill is instructions and data:
the catalog, the schemas, the specialist profiles, the packs and these references. Executable
helpers are optional, and they come from two places.

**`python -m pip install sechelix`** installs the `sechelix` CLI (`doctor`, `audit`, `runs`,
`coverage`, `replay`, `report`, `mcp`) and makes the helper modules below importable. `pipx` and
`uv tool` install the CLI but keep the modules inside their own environment, so use `pip` in the
environment you are working in when you intend to import `sechelix_core`.

**The source repository** (`git clone https://github.com/omarmohelal/SecHelix`) additionally
holds the release-gate script, the report renderer, the scanner adapters and the validators.
They are not in the wheel.

Read the rest of this file only when one of those is available. If neither is, run the workflow
from the instructions and the contracts alone: every phase in `SKILL.md` is executable by hand.

## Versioned contracts

- 22 JSON Schema contracts (Draft 2020-12) under `schemas/` cover scope, attack surface,
  applicability, evidence, findings, reports, catalog, extensions, source trust, knowledge graph,
  lesson cards, live research packets, Gold Check Packs, policy packs and related records. Use
  them instead of inventing parallel report shapes.
- All 546 catalog hypotheses in `catalog/checks.json` have explicit, stable IDs from the frozen
  manifest (21 families × 26 lenses).
- Reports derive Markdown, redacted JSON, SARIF 2.1.0 and escaped standalone HTML from one
  canonical JSON source.
- Release gates fail closed to `INCOMPLETE` for malformed or missing evidence.
- Public benchmark results remain `NOT_MEASURED` until a reproducible run emits signed inputs,
  configuration and outputs.

## Resource map

In the installed skill (data only):

- `references/methodology.md`: evidence and verification philosophy.
- `references/tooling.md`: scanner and tool adapter guidance.
- `references/sources.md`: standards and source references.
- `references/knowledge-engine.md`: source trust, rights, live research, confidence, graph,
  lesson-card, lab and de-identified learning policy.
- `references/gold-check-packs.md`: reusable check-pack and Variant Hunter contracts that cannot
  bypass applicability or verification.
- `knowledge/`: source registry, provenance graph and lesson cards.
- `catalog/checks.json`: structured hypothesis catalog.
- `agents/`: specialist reviewer profiles.
- `schemas/`: versioned scope, evidence, finding and report contracts.
- `gold-packs/`: reusable check packs.
- `policies/`: public release-gate policy examples; keep real organization policy packs private.
- `examples/`: scope and report examples.

In a repository clone only:

- `scripts/security_gate.py`: report and release gate.
- `scripts/applicability.py`: deterministic applicability decision helper.
- `scripts/attack_surface.py`: attack-surface and Mermaid graph helper.
- `scripts/validate_catalog.py`, `scripts/validate_knowledge.py`,
  `scripts/validate_gold_packs.py`: catalog, knowledge and Gold Pack validation.
- `adapters/`: normalized Semgrep, CodeQL/SARIF, OSV, Gitleaks, Trivy, npm/pnpm audit,
  Playwright, ZAP and Nuclei evidence adapters.
- `reports/`: canonical Markdown/JSON/SARIF/HTML report renderer.

## Helper modules

Importable after `python -m pip install sechelix`, and from a repository clone.

| Module | Use |
|---|---|
| `sechelix_core.untrusted_repo` | zero-trust enforcement for `UNTRUSTED_REPO` reviews |
| `sechelix_core.attack_chains` | composes verified findings into named chains |
| `sechelix_core.diff_review` | differential classification of a change set |
| `sechelix_core.variant_rules` | generates variant-hunting rules from verified findings |
| `sechelix_core.patch_mode` | reviewable patch proposals; never applies anything |
| `sechelix_core.revision` | binds a report to the revision it inspected |

## Typical commands

From the installed package:

```bash
sechelix doctor                       # which components and executors are available
sechelix audit . --executor claude-code
sechelix report --format markdown
sechelix mcp /path/to/the/repository  # read-only MCP adapter over one root
```

From a repository clone:

```bash
python scripts/attack_surface.py --help
python scripts/applicability.py --help
python scripts/validate_knowledge.py
python -m adapters.cli --help
python -m reports.report_renderer examples/report.example.json --format markdown
python scripts/security_gate.py examples/report.example.json --policy policies/default.json
python scripts/security_gate.py report.json --policy policies/default.json \
  --current-commit "$(git rev-parse HEAD)"
```
