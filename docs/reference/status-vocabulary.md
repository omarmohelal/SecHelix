# Status vocabulary

SecHelix uses a small number of words repeatedly, but the same word can belong to different contracts. This page is an index of those contracts. It does **not** create new states and it does not override the linked schema or source file.

The rule for reading any status is: identify the vocabulary first, then read only the assertion that vocabulary permits. `UNKNOWN` is not an absence, `NOT_APPLICABLE` is not a pass, `CANDIDATE` is not a finding, `DOCUMENTED` is not `VERIFIED`, and `NOT_MEASURED` is not `0.0`.

## Colliding words

- **`BLOCKED`** has several meanings. An applicability decision is blocked when the hypothesis cannot be evaluated under the current authorization/evidence state; a release gate is blocked when known evidence prevents release; Gold Pack calibration can be blocked when measurement itself cannot be completed. Read the enclosing object before interpreting the word.
- **`VERIFIED`** can describe a finding/verifier outcome, an evaluation verification status, or a compatibility observation. These are independent vocabularies. A host integration being `VERIFIED` says nothing about security accuracy.
- **`UNKNOWN`** appears in applicability/capability state and means the evidence needed to decide was not obtained. It must not be converted to `ABSENT`, `NOT_APPLICABLE`, or a clean result.
- **`FALSE_POSITIVE`** is a finding/verifier outcome and is also a documented evaluation verification status. In both cases a candidate was raised and refuted; it is not a synonym for `CLEAN` source code.

Two current contract gaps are worth keeping visible rather than silently reconciling them:

1. [`scope-v1.schema.json`](../../schemas/scope-v1.schema.json) and [`evidence-v1.schema.json`](../../schemas/evidence-v1.schema.json) include `UNTRUSTED_REPO` as an execution mode, while the top-level `mode` in [`report-v1.schema.json`](../../schemas/report-v1.schema.json) currently allows only `STATIC`, `LOCAL`, `STAGING`, and `PRODUCTION_SAFE`. A report therefore cannot currently represent `UNTRUSTED_REPO` in that top-level field without violating its schema.
2. [`evals/blind-packet/RUN.md`](../../evals/blind-packet/RUN.md) documents `NOT_RUN`, `VERIFIED`, and `FALSE_POSITIVE` for `verification_status`; [`evals/run_evals.py`](../../evals/run_evals.py) additionally recognizes `DUPLICATE_ROOT_CAUSE`, but does not currently reject an arbitrary unknown verification-status string. This page lists the documented/recognized values and does not pretend an enum is enforced where none exists.

## Applicability outcome

Authoritative source: [`schemas/applicability-output-v1.schema.json`](../../schemas/applicability-output-v1.schema.json).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `APPLICABLE` | The recorded architecture/scope evidence is sufficient to select this hypothesis for review. It says nothing about whether the hypothesis will be confirmed. | [`applicability-output-v1.schema.json`](../../schemas/applicability-output-v1.schema.json) |
| `NOT_APPLICABLE` | Evidence establishes that the capability needed for this hypothesis is absent for the scoped target. This is an applicability decision, not a security pass. | [`applicability-output-v1.schema.json`](../../schemas/applicability-output-v1.schema.json) |
| `UNKNOWN` | The capability/evidence needed to decide applicability was not established. The hypothesis is unresolved, not absent. | [`applicability-output-v1.schema.json`](../../schemas/applicability-output-v1.schema.json) |
| `BLOCKED` | Applicability could not be evaluated because authorization or an explicit/capability block prevents the required assessment. | [`applicability-output-v1.schema.json`](../../schemas/applicability-output-v1.schema.json) |

The schema's reason codes make the distinction concrete: `SCOPE_NOT_AUTHORIZED` and `EXPLICIT_BLOCK` are different from `CAPABILITY_ABSENT`, `CAPABILITY_UNKNOWN`, and `CAPABILITY_BLOCKED`.

## Capability state

Authoritative sources: [`schemas/applicability-input-v1.schema.json`](../../schemas/applicability-input-v1.schema.json) and the normalized `capability_states` in [`schemas/applicability-output-v1.schema.json`](../../schemas/applicability-output-v1.schema.json).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `PRESENT` | The architecture record states that the named capability exists, with a reason and optional evidence references. | [`applicability-input-v1.schema.json`](../../schemas/applicability-input-v1.schema.json) |
| `ABSENT` | The architecture record establishes that the named capability is absent. It is stronger than `UNKNOWN`. | [`applicability-input-v1.schema.json`](../../schemas/applicability-input-v1.schema.json) |
| `UNKNOWN` | The architecture record cannot establish presence or absence. | [`applicability-input-v1.schema.json`](../../schemas/applicability-input-v1.schema.json) |
| `BLOCKED` | The capability cannot be assessed under the recorded evidence/access state. | [`applicability-input-v1.schema.json`](../../schemas/applicability-input-v1.schema.json) |
| `UNDECLARED` | The normalized output has no declared capability record for the capability being referenced. This value exists in output normalization, not in an input capability object. | [`applicability-output-v1.schema.json`](../../schemas/applicability-output-v1.schema.json) |

## Release gate

Authoritative source: [`schemas/report-v1.schema.json`](../../schemas/report-v1.schema.json); the gate recomputes the decision rather than trusting prose in a report.

| Value | What it asserts | Authoritative source |
|---|---|---|
| `PASS` | The release-gate rules evaluated by SecHelix have no unresolved condition that requires known-risk or fail-closed handling. It is not a guarantee that the software is vulnerability-free. | [`report-v1.schema.json`](../../schemas/report-v1.schema.json) |
| `PASS_WITH_KNOWN_RISK` | Release is allowed only with a separately recorded known/accepted risk under the policy that produced the decision. | [`report-v1.schema.json`](../../schemas/report-v1.schema.json) |
| `BLOCKED` | Known evidence or policy prevents release. This is stronger than `INCOMPLETE`: something known is release-blocking. | [`report-v1.schema.json`](../../schemas/report-v1.schema.json) |
| `INCOMPLETE` | Required evidence, verification, tooling, integrity, or coverage is missing, so SecHelix refuses to produce a clean release decision. | [`report-v1.schema.json`](../../schemas/report-v1.schema.json) |

## Verification depth

Authoritative source: the `run.verification_depth` field in [`schemas/report-v1.schema.json`](../../schemas/report-v1.schema.json).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `NONE` | No verification pass is recorded for the run. | [`report-v1.schema.json`](../../schemas/report-v1.schema.json) |
| `SELF_REVIEW` | Material claims were challenged only within the same review path/session boundary; this is weaker than an independent verifier. | [`report-v1.schema.json`](../../schemas/report-v1.schema.json) |
| `INDEPENDENT` | A separate verifier path challenged material claims independently. | [`report-v1.schema.json`](../../schemas/report-v1.schema.json) |
| `INDEPENDENT_MULTI_MODEL` | Independent verification used multiple model paths; agreement still has to be backed by evidence rather than model reputation. | [`report-v1.schema.json`](../../schemas/report-v1.schema.json) |

## Finding claim status

Authoritative source: [`schemas/finding-v1.schema.json`](../../schemas/finding-v1.schema.json).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `HYPOTHESIS` | A security claim is under investigation and has not earned a verified vulnerability conclusion. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `VERIFIED` | The finding's required evidence chain and verification record support the security claim. For High/Critical findings, project contracts require independent verification. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `LIKELY_BUT_UNPROVEN` | Evidence makes the claim plausible but required proof is still missing; it must not be reported as verified. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `FALSE_POSITIVE` | The candidate was investigated and refuted. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `DUPLICATE_ROOT_CAUSE` | The observation is real/relevant but is represented by another primary finding with the same recorded root cause rather than counted as an independent vulnerability. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `BLOCKED_BY_ENVIRONMENT` | The environment/access state prevented the evidence needed to verify or refute the candidate. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |

The nested verifier `outcome` has the same substantive outcomes plus `NOT_RUN`; it is a verifier result, not a replacement for the finding's own `status` field.

## Severity

Authoritative source: [`schemas/finding-v1.schema.json`](../../schemas/finding-v1.schema.json).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `CRITICAL` | SecHelix records the finding at the highest severity tier; the claim still has to satisfy the evidence/verification contract. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `HIGH` | SecHelix records the finding at the High severity tier; severity does not waive independent verification. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `MEDIUM` | SecHelix records the finding at the Medium severity tier. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `LOW` | SecHelix records the finding at the Low severity tier. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `INFO` | The record is informational rather than a higher-impact security finding. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |
| `UNASSIGNED` | No SecHelix severity has been assigned. Scanner severity is not silently copied into this field. | [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json) |

Finding confidence is a separate enum: `HIGH`, `MEDIUM`, `LOW`, `NOT_ASSESSED`. Confidence and severity answer different questions and neither substitutes for verification.

## Evidence state

There are two intentionally different layers.

### Adapter candidate state

Authoritative source: [`adapters/base.py`](../../adapters/base.py).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `CANDIDATE` | A third-party scanner/tool observation has been normalized into candidate evidence. It has not become a SecHelix finding. | [`adapters/base.py`](../../adapters/base.py) |
| `UNASSESSED` | The adapter has assigned no SecHelix assessment, severity, or verification outcome. Scanner labels remain under `tool_signal.trusted_for_assessment: false`. | [`adapters/base.py`](../../adapters/base.py) |

### Canonical evidence lifecycle

Authoritative source: [`schemas/evidence-v1.schema.json`](../../schemas/evidence-v1.schema.json).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `RAW` | The evidence artifact is recorded before SecHelix normalization/confirmation. | [`evidence-v1.schema.json`](../../schemas/evidence-v1.schema.json) |
| `NORMALIZED` | The evidence has been normalized into the canonical evidence contract but is not thereby confirmed as proof of a finding. | [`evidence-v1.schema.json`](../../schemas/evidence-v1.schema.json) |
| `CONFIRMED` | The evidence record itself has been confirmed for the statement it supports. Confirmation of evidence is not automatically confirmation of every finding that cites it. | [`evidence-v1.schema.json`](../../schemas/evidence-v1.schema.json) |
| `REJECTED` | The evidence item was evaluated and rejected for the claim it was meant to support. | [`evidence-v1.schema.json`](../../schemas/evidence-v1.schema.json) |

## Execution mode

Authoritative scope source: [`schemas/scope-v1.schema.json`](../../schemas/scope-v1.schema.json). Canonical evidence also records these modes in [`schemas/evidence-v1.schema.json`](../../schemas/evidence-v1.schema.json).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `STATIC` | The assessment is limited to source/config/schema reasoning and does not authorize dynamic target traffic. | [`scope-v1.schema.json`](../../schemas/scope-v1.schema.json) |
| `LOCAL` | Dynamic verification is limited to local/controlled targets and fixtures under the recorded scope. | [`scope-v1.schema.json`](../../schemas/scope-v1.schema.json) |
| `STAGING` | Dynamic verification targets an explicitly authorized non-production environment under scope restrictions. | [`scope-v1.schema.json`](../../schemas/scope-v1.schema.json) |
| `PRODUCTION_SAFE` | Only explicitly bounded, non-destructive production verification allowed by the recorded restrictions is in scope. | [`scope-v1.schema.json`](../../schemas/scope-v1.schema.json) |
| `UNTRUSTED_REPO` | Repository-authored instructions are treated as data rather than control; capabilities are denied by default and require explicit operator escalation. | [`scope-v1.schema.json`](../../schemas/scope-v1.schema.json) |

`UNTRUSTED_REPO` is currently absent from the top-level report `mode` enum; see the contract-gap note at the top of this page.

## Gold Pack lifecycle

Authoritative source: [`schemas/gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `REFERENCE` | The pack is a reference check pack; it must not self-promote to a stronger project lifecycle. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |
| `COMMUNITY` | The pack is classified in the Community lifecycle by the project. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |
| `INCUBATING` | The pack is in a project incubation lifecycle rather than the strongest lifecycle. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |
| `OFFICIAL` | The pack is classified as Official by the project; this does not create a performance measurement by itself. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |

## Gold Pack calibration status

Authoritative source: [`schemas/gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `MEASURED` | Calibration has a recorded measurement with a sample size; readers must still inspect its scope and notes. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |
| `NOT_MEASURED` | No calibration result exists. It is not zero accuracy and not evidence that the pack is ineffective. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |
| `INSUFFICIENT_SAMPLE` | Some calibration data exists or was attempted, but the sample is too small to support a published calibration claim. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |
| `BLOCKED` | The calibration process could not produce the required measurement under its recorded constraints. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |

## Variant classification

The exact result contract is a constant in [`schemas/gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json): `EXACT | VARIANT | REFUTED | BLOCKED; exact and variant matches remain hypotheses until verified`.

| Value | What it asserts | Authoritative source |
|---|---|---|
| `EXACT` | The candidate matches the verified seed's anchored invariant/boundary/action pattern exactly, but remains a hypothesis until independently verified. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |
| `VARIANT` | The candidate preserves the security invariant while changing a permitted variant dimension; it remains a hypothesis until independently verified. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |
| `REFUTED` | The candidate was refuted by evidence/compensating control rather than promoted. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |
| `BLOCKED` | Required evidence for variant classification could not be obtained; it is not an exact/variant match. | [`gold-check-pack-v1.schema.json`](../../schemas/gold-check-pack-v1.schema.json) |

## Evaluation labels

Authoritative sources: [`evals/run_evals.py`](../../evals/run_evals.py) and the published procedure [`evals/blind-packet/RUN.md`](../../evals/blind-packet/RUN.md).

### Prediction label

| Value | What it asserts | Authoritative source |
|---|---|---|
| `VULNERABLE` | For the blind single-file task, the evaluator predicts that the case contains an exploitable security weakness. | [`run_evals.py`](../../evals/run_evals.py) |
| `CLEAN` | For the blind single-file task, the evaluator predicts that the case does not contain the exploitable weakness posed by the task. It is a fixture label, not a general production security certificate. | [`run_evals.py`](../../evals/run_evals.py) |

### Evaluation verification status

| Value | What it asserts | Authoritative source |
|---|---|---|
| `NOT_RUN` | No independent verification was performed for that prediction; this is the default in the scorer. | [`run_evals.py`](../../evals/run_evals.py) |
| `VERIFIED` | The procedure says to use this only when a raised claim was independently reconstructed. | [`blind-packet/RUN.md`](../../evals/blind-packet/RUN.md) |
| `FALSE_POSITIVE` | A candidate was raised and then refuted. | [`blind-packet/RUN.md`](../../evals/blind-packet/RUN.md) |
| `DUPLICATE_ROOT_CAUSE` | The scorer recognizes this string when computing `duplicate_root_cause_rate`; the blind procedure does not currently document it in its packet example. | [`run_evals.py`](../../evals/run_evals.py) |

The scorer does not currently enforce a closed enum for `verification_status`; see the contract-gap note at the top of this page.

## Compatibility status

Authoritative source: [`docs/reference/compatibility.md`](compatibility.md).

| Value | What it asserts | Authoritative source |
|---|---|---|
| `VERIFIED` | SecHelix was cold-installed or loaded and exercised in that integration path, with the result recorded by this project. | [`compatibility.md`](compatibility.md) |
| `DOCUMENTED` | The host vendor documents the discovery mechanism, but this project has not recorded SecHelix loading in that host through the stated path. | [`compatibility.md`](compatibility.md) |
| `MODEL_COMPATIBLE` | The portable bundle can be presented as files, but the host's native skill loader has not been verified. | [`compatibility.md`](compatibility.md) |
| `UNVERIFIED` | Neither a recorded project test nor vendor documentation backs that specific integration path. | [`compatibility.md`](compatibility.md) |
| `NOT_SHIPPED` | The path is deliberately absent; the omission is intentional rather than accidental. | [`compatibility.md`](compatibility.md) |

## Related status fields

These are not part of issue #16's collision list, but they are common in reports and are defined by the same finding contract:

- **Regression status:** `NOT_RUN`, `PASS`, `FAIL`, `NOT_PRACTICAL` in [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json).
- **Finding resolution:** `OPEN`, `FIXED`, `ACCEPTED_RISK`, `FALSE_POSITIVE`, `DUPLICATE_ROOT_CAUSE`, `DEFERRED` in [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json).
- **Finding confidence:** `HIGH`, `MEDIUM`, `LOW`, `NOT_ASSESSED` in [`finding-v1.schema.json`](../../schemas/finding-v1.schema.json).
- **Repository trust posture:** `DATA_ONLY` or `TRUSTED_CONTROL` in [`scope-v1.schema.json`](../../schemas/scope-v1.schema.json); in `UNTRUSTED_REPO` mode, repository content cannot declare itself `TRUSTED_CONTROL`.

When a new status vocabulary is added to a schema or public source, update this page from that source rather than inventing a parallel definition here.
