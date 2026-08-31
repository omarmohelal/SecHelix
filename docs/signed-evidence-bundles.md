# Signed evidence bundle design

Status: **design only — signing is not yet an implemented or published feature**.

The goal is to make a final report and its evidence manifest tamper-evident and
traceable to an approved release workflow. A signature does not certify that a
finding is true; verification and regression evidence still determine trust.

## Proposed bundle

```text
bundle/
  manifest.json
  report.json
  report.md
  report.sarif
  report.html
  evidence/                 # optional, redacted, policy-approved artifacts
  policy/public-policy.json # private policy values may remain referenced by digest
  attestations/
    signature
    certificate-or-identity
```

`manifest.json` should include:

- bundle/schema version and bundle ID;
- repository identity and immutable commit;
- scope ID and execution mode;
- creation time;
- SecHelix version/commit;
- policy name/version/digest;
- normalized SHA-256 digest, media type, and size for every included file;
- gate outcome;
- signing subject/workflow identity;
- explicit exclusions and redaction statement.

Canonical JSON must use deterministic serialization before hashing. Paths must
be relative, normalized, unique, and forbidden from escaping the bundle root.
Archive extraction must perform the same containment checks.

## Signing and verification

Organizations may use an approved KMS/HSM-backed key or a keyless workload
identity system such as Sigstore-compatible tooling. The chosen implementation
should:

1. sign the manifest digest, not an ambiguous archive byte stream;
2. bind repository, commit, workflow, and environment identity;
3. publish or retain the trust root and identity policy;
4. verify every file digest before accepting the signature;
5. verify certificate/identity constraints and transparency evidence where used;
6. record revocation/rotation and verification events;
7. fail closed on missing, extra, duplicate, or path-escaping files.

Private keys, seed phrases, CI signing credentials, and provider API secrets must
never enter the bundle or public repository.

## Threats not solved by signatures

- incomplete scope or missing evidence;
- a verifier that did not independently reconstruct the finding;
- a malicious but authorized signer;
- secrets captured before redaction;
- compromised source or runner before artifact generation;
- long-term trust-root or timestamp validation.

Implement signing only with fixtures, negative verification tests, key rotation,
and an incident/revocation runbook.
