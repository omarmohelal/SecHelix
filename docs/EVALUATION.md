# SecHelix Evaluation Protocol

SecHelix does not claim benchmark performance until a result is reproducible. This document defines the minimum evidence required before publishing any accuracy, recall, false-positive, or coverage number.

## Goals

Measure whether SecHelix can:

- identify applicable security hypotheses;
- avoid reporting clean behavior as vulnerable;
- verify real security-boundary failures;
- reject false positives during independent verification;
- find sibling/variant instances after a confirmed root cause;
- preserve uncertainty as `UNKNOWN` or `BLOCKED` instead of guessing;
- produce useful root-cause fixes and regression proof;
- make a correct fail-closed release decision.

## Required evaluation record

Every published run must record:

- SecHelix commit/version;
- fixture or target commit/version;
- environment and execution mode;
- model/provider/version where available;
- agent host/client;
- enabled scanners/tools and versions;
- prompt/instruction used;
- deterministic configuration and seeds where available;
- start/end timestamps;
- expected labels;
- observed labels;
- verifier outcome;
- report/retest artifacts;
- known limitations and blocked checks.

A screenshot alone is not a benchmark artifact.

## Core metrics

### Verified precision

`verified true positives / all reported verified findings`

A candidate rejected by the verifier is not a verified finding and must remain visible in false-positive/rejection accounting.

### Detection recall

`verified expected vulnerabilities found / total verified expected vulnerabilities in the fixture set`

Only use fixture sets whose ground truth is documented.

### False-positive rejection rate

`false candidates correctly rejected / all intentionally false candidates presented to the workflow`

This directly measures one of SecHelix's central claims: verification should reduce unsupported findings.

### Applicability accuracy

Measure correct `APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`, and `BLOCKED` classification. Do not collapse `UNKNOWN` or `BLOCKED` into success.

### Regression-proof rate

For verified findings that receive a fix, measure the fraction with a regression test that fails before the fix and passes after it, plus a successful retest of the original claim.

### Release-gate accuracy

Evaluate whether the final `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, or `INCOMPLETE` decision matches the documented evidence policy.

## Minimum first public benchmark

The first measured release does not need a huge corpus. It needs honest ground truth and reproducibility.

Recommended minimum:

1. at least one clean and one vulnerable case for authorization;
2. at least one clean and one vulnerable injection/dataflow case;
3. at least one state-machine/business-logic pair;
4. at least one race/idempotency pair where deterministic reproduction is possible;
5. at least one secrets/supply-chain pair;
6. at least one AI/agent/MCP pair if claiming runtime AI-security evaluation.

Each case should be non-trivial enough that a keyword match alone cannot solve it.

## Real-repository case studies

Real repositories are separate from synthetic benchmark scores. A public case study must include:

- authorization to test;
- repository and commit;
- relevant SecHelix commit;
- safe description of the failed boundary;
- evidence trail;
- fix PR/commit when public;
- regression proof;
- attribution permission;
- explicit statement if the finding was previously known.

Add qualifying results to `TROPHY_CASE.md`; do not manufacture trophy entries from private or unverifiable work.

## Comparison policy

Do not publish "better than tool X" claims unless:

- the same targets and ground truth are used;
- tools receive comparable access;
- metric definitions are identical;
- configurations and versions are recorded;
- raw results can be independently inspected;
- limitations are stated.

Scanner finding counts are not an accuracy metric.

## Reporting template

```text
SecHelix commit:
Target/fixture version:
Host/model:
Mode:
Tools:
Cases:
Expected vulnerable:
Expected clean:
Verified TP:
Verified FP:
False candidates rejected:
Verified FN:
Unknown:
Blocked:
Verified precision:
Detection recall:
FP rejection rate:
Regression-proof rate:
Release-gate accuracy:
Artifacts:
Limitations:
```

The blind label suite has one run that satisfies this protocol
(`evals/results/claude-sonnet-5-blind-2026-09-02.json`). Until a run exercises the
full workflow, applicability accuracy, regression-proof rate and release-gate
accuracy remain `NOT_MEASURED`.
