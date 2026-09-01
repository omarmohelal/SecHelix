# SecHelix architecture

SecHelix is deliberately split into seven layers so the methodology can remain portable while vendor-specific adapters evolve independently.

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
│  Knowledge resolution                                      │
│  source trust · rights · research · graph · lesson cards   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  Coverage model                                             │
│  21 families × 26 lenses = 546 hypothesis slots            │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│  Gold Packs + Variant Hunter                                │
│  reusable invariants · fingerprints · sibling hypotheses   │
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

The canonical `skills/sechelix/SKILL.md` owns methodology. Vendor adapters may add invocation/orchestration hints but must not fork safety, severity, evidence, or verification semantics.

## Coverage model

`catalog/checks.json` is a structured cross product rather than a static payload list. Families identify where a security property lives; lenses identify how an invariant can fail. The combination produces a hypothesis that must be marked applicable before testing.

This model makes it easy to add a new family or verification lens without copying hundreds of near-identical checks.

## Gold Packs and variants

Gold Check Packs deepen selected catalog hypotheses with threat models,
framework fingerprints, detection layers, false-positive filters, safe
validation, independent refutation, canonical remediation, and regression
proof. Packs do not increase the 546-slot catalog count and cannot mark their
own results verified.

The deterministic Variant Hunter compares a verified seed invariant with sibling
paths. It returns `EXACT`, `VARIANT`, `REFUTED`, or `BLOCKED`; exact and variant
matches remain hypotheses and re-enter the normal evidence workflow.

## Knowledge resolution

`knowledge/source-registry.json` is the executable authority and rights boundary
for external knowledge. It records trust tier, publisher independence, license
state, allowed uses, and review cadence. `HUMAN_ONLY` curriculum sources cannot
enter automated research, datasets, embeddings, training, or evaluation.

Live research packets use deterministic confidence states and preserve dates,
exact versions, contradictions, and source provenance. The versioned graph links
CWE/CAPEC/OWASP/ASVS concepts without treating label similarity as proof, while
lesson cards store original SecHelix detection and verification guidance rather
than copied source prose.

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

## Community extension boundary

Public adapters and packs enter through `extensions/registry.json`. A submitted
manifest declares all requested authority and is structurally limited to safe
defaults. Registration does not execute or install code automatically; it creates a
reviewable identity and lifecycle record. `COMMUNITY`, `INCUBATING`, and `OFFICIAL`
are distribution trust channels, not evidence confidence levels.

Promotion requires a separate maintainer review record with fixture proof. An
extension can contribute observations or policy, but it cannot redefine the
canonical authorization, evidence, verification, or severity contracts.
