# SecHelix architecture

SecHelix is deliberately split into five layers so the methodology can remain portable while vendor-specific adapters evolve independently.

```text
┌─────────────────────────────────────────────────────────────┐
│  Agent / model adapters                                     │
│  Claude · OpenAI/Codex · GitHub/Copilot · generic agents   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  Canonical SKILL.md                                         │
│  scope · mapping · applicability · verification · fix       │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  Coverage model                                             │
│  21 families × 26 lenses = 546 hypothesis slots            │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  Evidence adapters                                          │
│  static · dependency · browser · API · DB · CI · scanners   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  Verification + release gate                                │
│  verifier · regression · report · pass/block decision       │
└─────────────────────────────────────────────────────────────┘
```

## Canonical truth

The root `SKILL.md` owns methodology. Vendor adapters may add invocation/orchestration hints but must not fork safety, severity, evidence, or verification semantics.

## Coverage model

`catalog/checks.json` is a structured cross product rather than a static payload list. Families identify where a security property lives; lenses identify how an invariant can fail. The combination produces a hypothesis that must be marked applicable before testing.

This model makes it easy to add a new family or verification lens without copying hundreds of near-identical checks.

## Evidence adapters

External tools produce normalized candidate evidence. Future adapters may ingest SARIF or scanner JSON. SecHelix does not trust a tool's severity automatically.

## Verification boundary

High/Critical candidates are independently reconstructed. This is intentionally a different role from the original hunter to reduce confirmation bias and correlated model errors.

## Company extensions

Organizations can add policy packs without changing the open core:

- company-specific roles and trust boundaries;
- forbidden deployment states;
- required scanners;
- severity overrides for regulated assets;
- release gates;
- custom report schemas;
- environment-specific safe-test rules.

Future hosted/enterprise tooling should orchestrate these policies without changing the portable skill format.