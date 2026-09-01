# Evidence proof bundles

A security claim you cannot check is a claim you have to take on trust.

A proof bundle is the opposite: every artifact behind one verified finding, written as files, with a
manifest and a digest over the manifest, so a recipient can verify that what they received is what
was produced.

This is the unit of external proof. A trophy-case entry, a disclosure email and a customer-facing
report are the same shape — a claim plus its evidence — and shipping that as a directory rather than
a paragraph is what makes it falsifiable by the person receiving it.

## Contents

| File | Holds |
|---|---|
| `finding.json` | The claim: id, title, severity, confidence, surface, evidence chain |
| `evidence.json` | Only the evidence records this finding actually cites |
| `verification.json` | Outcome, whether the verifier was independent, and the refutation attempted |
| `root-cause.json` | The recorded fix and any residual risk |
| `patch.diff` | The proposed change, when one was supplied |
| `regression.json` | The command, the assertion, and the status **as recorded** |
| `retest.json` | Retest and regression-phase evidence |
| `manifest.json` | A SHA-256 for every file, plus what is deliberately absent |
| `manifest.sha256` | A digest over the manifest |

## What it refuses to do

**Only verified findings export.** A bundle is a proof, and there is nothing to prove about a
candidate that was never confirmed. Everything else is refused *with its reason*, so a caller sees
what was excluded rather than silently receiving less. Running this over the published case study
exports the verified clickjacking finding and refuses the refuted XSS candidate.

**Redaction is on by default.** Bundles get emailed to strangers. AWS keys, GitHub tokens, OpenAI
keys, Slack tokens, private key headers, bearer tokens, JWTs, password assignments and home
directory paths are stripped before anything is written, and the manifest records that redaction
occurred and how many values it touched. The patterns are deliberately broad: a false redaction
costs a reader one question, a missed one costs a credential.

**Nothing is upgraded on the way out.** If regression status was `NOT_RUN` in the report, it is
`NOT_RUN` in the bundle. Export is a serialization step, not a place where evidence improves.

**Absent files are listed, not faked.** `manifest.absent` names every standard artifact the report
had no material for, so a reader can tell "not applicable" from "we forgot".

## What the digest does and does not prove

`manifest.sha256` covers `manifest.json`, which records a digest for every file. Tampering with an
artifact changes its recorded hash; tampering with the manifest changes the digest.

**This is not a signature.** It detects accidental modification and casual editing. It proves
nothing about origin, and a motivated forger with write access can regenerate both. The manifest
says so in its own `integrity_note` rather than letting the presence of hashes imply cryptographic
provenance the bundle does not have.

## Usage

```python
from sechelix_core.proof_bundle import export_bundles, verify_bundle

result = export_bundles(report, diffs={"SHX-F-1": patch_text})
for bundle in result["bundles"]:
    assert verify_bundle(bundle["files"]) == []
```

`verify_bundle` is the recipient's side: hand it the files you received and it returns the list of
problems. An empty list means the bundle is internally consistent.

## Related

- [Patch mode](patch-mode.md) — where `patch.diff` comes from
- [Trophy case](../research/trophy-case.md) — the entry criteria a bundle is meant to satisfy
