# SecHelix Knowledge Engine

This directory is the checked-in, rights-aware foundation for turning current
security information into evidence-backed review guidance. It is deliberately
small: the first release proves the contracts and safety boundaries before any
large corpus is ingested.

## Surfaces

- `source-registry.json` records authority, independence, license state,
  permitted uses, and refresh cadence for every source.
- `graph/relationships.json` holds versioned CWE, CAPEC, OWASP, ASVS, and
  SecHelix relationships with explicit provenance.
- `lesson-cards/` stores compact detection, safe-test, false-positive,
  remediation, and regression guidance. Cards summarize; they do not mirror
  third-party prose.

The live-research packet contract is demonstrated in
`examples/research-packet.example.json`. Runtime confidence calculation lives in
`sechelix_core/knowledge.py`.

## Hard boundary

No source is ingested merely because it is public on the web. The registry must
allow the exact operation first. `HUMAN_ONLY` sources may be opened by a person
under their terms, but SecHelix must not crawl, copy, embed, train on, or benchmark
against them without separate written permission.

Run `python scripts/validate_knowledge.py` after changing any registry, graph,
lesson card, or research packet artifact.
