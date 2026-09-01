# Gold Check Packs and Variant Hunter

Gold Check Packs are provenance-bound, reusable investigation plans for selected
SecHelix catalog hypotheses. They deepen the existing 546-slot coverage model;
they do not create a second catalog and do not imply benchmark performance.

Each pack records:

- threat model and applicability evidence;
- framework fingerprints as leads, never proof;
- trust boundary, sink classes, and layered detection signals;
- safe local or static validation steps;
- false-positive filters and independent refutation tests;
- root-cause, canonical remediation, and regression guidance;
- variant anchors and generalization dimensions;
- mappings, calibration state, provenance, and limitations.

The v1 contract requires non-destructive defaults, forbids production mutation,
and requires independent verification. Pack source IDs must exist in the
rights-aware source registry, catalog IDs must exist in the canonical catalog,
and regression fixture IDs must resolve locally.

## Variant result contract

`sechelix_core.variant_hunter` compares a seed finding signature with candidate
sibling paths:

- `EXACT` — all anchors and variant dimensions match;
- `VARIANT` — security invariant, boundary, and action match while one or more
  actor/object/framework/enforcement dimensions differ;
- `REFUTED` — the path is unreachable, an evidenced control is enforced, or an
  anchor does not match;
- `BLOCKED` — reachability or control evidence is still unknown.

`EXACT` and `VARIANT` are discovery classifications. Their claim status remains
`HYPOTHESIS` until applicability, evidence, and independent verification are
complete.

Validate the checked-in packs with:

```bash
python scripts/validate_gold_packs.py
python -m unittest tests.test_gold_packs -v
```
