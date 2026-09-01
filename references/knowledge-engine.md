# Knowledge engine and live research

Use this reference when a review depends on current vulnerability intelligence,
an unfamiliar package or framework, a recent cloud/provider change, or a
reusable lesson-card/graph update. It extends the evidence workflow; it never
replaces repository evidence or safe reproduction.

## Trust order

1. official standards, maintainers, vendors, and public authorities;
2. official advisories and machine-readable vulnerability records;
3. primary research and official tool query/rule repositories;
4. reputable independent technical analysis;
5. community discussion as a lead only.

The machine-readable policy lives in `knowledge/source-registry.json`. Each
entry carries an independence group, trust tier, license state, allowed uses,
and refresh budget. A public URL is not permission to crawl, copy, embed, train,
or benchmark.

## Rights and platform-policy gate

Before retrieval or ingestion:

1. resolve the source ID in the registry;
2. check that the exact operation is `true` in `allowed_uses`;
3. review the pinned artifact/revision when `per_artifact_review` is true;
4. retain source URL, publisher, retrieval time, version, license, and required
   attribution;
5. store normalized facts and original SecHelix analysis, not copied prose;
6. stop if terms, provenance, or redistribution rights are unclear.

PortSwigger Web Security Academy, TryHackMe, and Hack The Box are registered as
`HUMAN_ONLY`. Their links may help a person plan study, but SecHelix must not use
autonomous agents to access the platforms, copy their content, create embeddings
or datasets, or use their content for model training/evaluation without separate
written permission. The registry makes this boundary executable.

SARD is an aggregator. Review the selected suite's notices before ingestion.
OWASP Benchmark language repositories and utilities may have different licenses;
pin and review the exact repository. CodeQL query source is MIT-licensed, but the
separate CodeQL CLI has different terms. Semgrep Community Rules use the Semgrep
Rules License rather than a generic permissive license.

## Live research triggers

Create a `research-packet` when any of these is true:

- package or ecosystem behavior is unknown;
- a new CVE/advisory may affect the exact installed version;
- the relevant framework, database, cloud, or provider behavior changed recently;
- sources conflict;
- a candidate relies on an unfamiliar runtime behavior.

Research sequence:

1. identify the exact component, version, configuration, and deployment context;
2. search the subject vendor/maintainer and official standards first;
3. check OSV, NVD, CISA KEV, and GitHub Advisory Database as applicable;
4. add a second independent reputable source;
5. compare publication/update dates and version ranges;
6. return to code, configuration, lockfiles, and runtime evidence;
7. perform the smallest authorized reproduction when needed;
8. record contradictions and limitations instead of silently choosing a source.

## Research confidence

`sechelix_core.knowledge.expected_research_confidence` computes a narrow source
confidence state:

- `UNVERIFIED` — zero/one eligible source, unresolved contradiction, or missing
  version evidence;
- `SUPPORTED` — at least two independent Tier S/A/B sources support the claim;
- `HIGH_CONFIDENCE` — a Tier-S official advisory supports the exact version;
- `CONFIRMED` — code evidence and a bounded safe reproduction both exist.

This is not finding status. A `CONFIRMED` research fact still has to satisfy the
SecHelix evidence chain before it becomes a verified vulnerability.

## Knowledge graph

`knowledge/graph/relationships.json` connects versioned classification and
verification nodes. Every external node and every edge carries source IDs.
Initial relationships include:

```text
CWE-918 ← included by OWASP Top 10 A10:2021
   ↑
mitigated by ASVS 5.0.0 V1.3.6
   ↓
exploited through CAPEC-664
```

Add only relationships that are explicitly supported by the referenced release.
Do not infer a mapping because labels look similar.

## Lesson cards

Lesson cards distill reusable expertise into:

- detection signals;
- safe local tests;
- false-positive traps;
- remediation patterns;
- regression proof;
- graph mappings and source provenance.

Cards must be original summaries, target-independent, and useful for verification.
They must not contain weaponized payload collections or copied training-platform
content.

## Evaluation and isolated labs

The first ingestion priority is rights-reviewed SARD suites and the exact OWASP
Benchmark repositories needed for a benchmark. Run vulnerable applications only
in isolated containers/networks with no production credentials, no host mounts
that expose user data, bounded resources, deterministic reset, and explicit
authorization. Pair vulnerable fixtures with clean controls and measure both true
and false positives. Do not publish a capability score until inputs, revisions,
configuration, outputs, and license notices are reproducible.

## Learning without sensitive-memory leakage

Store de-identified failure classes, not customer code or findings. An exam or
review memory record may contain the lesson-card ID, missed invariant, evidence
gap, false-positive cause, and remediation misunderstanding. It must not retain
secrets, source snippets, personal data, target identifiers, credentials, or
exploit artifacts. Repeated mistakes should increase future review coverage, not
silently alter the evidence standard.

## Validation

Run:

```bash
python scripts/validate_knowledge.py
python scripts/validate_contract.py research-packet examples/research-packet.example.json
```

Unknown licensing, stale source reviews, conflicting sources, missing exact
versions, or absent local evidence are reasons to stay `UNVERIFIED`, not reasons
to guess.
