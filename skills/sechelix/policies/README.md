# Organization policy packs

Policy packs customize release decisions without changing SecHelix methodology.
Store real roles, private trust boundaries, asset names, accepted-risk approvals,
and regulatory rules in a private repository with access controls and review
history.

`default.json` blocks unresolved verified Critical/High findings, requires
independent verification for those severities, and returns `INCOMPLETE` for
integrity-critical unknowns. `strict.json` also blocks Medium findings and
turns integrity-critical unknowns into `BLOCKED`.

```bash
python scripts/security_gate.py report.json --policy policies/default.json
```

Supported controls include blocking severities, independent-verification and
regression requirements, accepted-risk approval fields, integrity-critical
unknowns, required evidence tools, forbidden deployment states, and severity overrides.
The gate never trusts the report's declared release recommendation. Empty,
malformed, or incomplete inputs return `INCOMPLETE` with exit code 2.
