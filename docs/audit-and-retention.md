# Audit logs and evidence retention

SecHelix audit data can contain security-sensitive architecture, rejected
hypotheses, employee identity, source excerpts, and remediation history. Treat
it as controlled security data rather than ordinary build output.

## Audit event design

Record append-only events for:

- scope creation and changes;
- applicability decisions and overrides;
- evidence ingestion with source and digest;
- verifier assignment and classification;
- finding severity/status/resolution changes;
- fix and regression evidence;
- accepted-risk creation, approval, expiration, and revocation;
- policy-pack version changes;
- gate decisions;
- report/bundle generation, access, export, and deletion.

Every event should include an event ID, UTC timestamp, actor or workload
identity, action, object type/ID, repository and commit, scope ID, policy digest,
previous-event hash where chaining is used, and a redacted metadata object.
Never put raw tokens, private keys, session cookies, seed phrases, or complete
production payloads in audit metadata.

[`../examples/audit-log.example.jsonl`](../examples/audit-log.example.jsonl) is
synthetic and illustrates the event shape without defining a production log
service.

## Retention classes

Define durations with legal, privacy, incident-response, and contractual owners:

| Class | Examples | Default direction |
|---|---|---|
| Ephemeral working data | raw scanner output, temporary source slices | Delete after normalization/verification unless needed for an active case |
| Release evidence | canonical report, gate decision, regression proof | Keep for the supported release lifetime plus the organization's audit window |
| Accepted risk | approval, rationale, compensating controls | Keep through expiration and review history |
| Security incident/legal hold | evidence explicitly placed on hold | Follow authorized hold; suspend normal deletion only for scoped records |
| Benchmark data | synthetic fixtures and measured run metadata | Retain for reproducibility; never mix in customer source |

Retention is not “keep forever.” Document deletion jobs, backup expiry,
geographic/storage restrictions, and how a repository or customer is purged.

## Integrity and access

- Use least-privilege read/write roles and separate evidence writers from policy/risk approvers.
- Encrypt stored evidence and transport using organization-approved controls.
- Prefer immutable or append-only storage for final gate decisions.
- Record export/access events and rate-limit bulk exports.
- Hash final artifacts and record the digest in the audit event.
- Test restoration and deletion, including backups.
- Redact before indexing in search/observability systems.

Signed evidence bundles can improve tamper detection but do not prove the audit
was complete or the original finding was correct.
