# Security policy

## Reporting a vulnerability in SecHelix

**Report privately first. Do not open a public issue for an unpatched vulnerability.**

Use GitHub Private Vulnerability Reporting:

**[Report a vulnerability →](https://github.com/omarmohelal/SecHelix/security/advisories/new)**

That form is private, visible only to the maintainer, and does not require an
email address or a PGP key. If the link returns a 404, private reporting has not
been enabled on the repository yet — open a public issue containing **only** the
sentence "I need a private channel to report a security issue" and no detail,
and the maintainer will open a private advisory to continue in.

Include:

- affected version or commit;
- affected file or path;
- threat model and prerequisites;
- a safe reproduction;
- impact;
- suggested mitigation, if known.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| Initial triage and severity assessment | 10 business days |
| Fix or documented mitigation | 90 days from acknowledgement |
| Public disclosure | after a fix ships, or by mutual agreement |

These are good-faith targets from a single maintainer, not a contractual SLA. If
a deadline slips you will be told why rather than ignored.

### Safe harbour

Good-faith security research on SecHelix itself will not be met with legal
action. "Good faith" means: you test only against your own copy of SecHelix, you
do not access or exfiltrate data belonging to anyone else, you do not degrade a
service other people rely on, and you give the maintainer a reasonable window
before public disclosure.

### Credit

Reporters are credited in the advisory and the changelog by default. Say so if
you would rather stay anonymous.

## What counts as a SecHelix vulnerability

SecHelix drives coding agents across repositories and can execute adapters with
declared authority. The classes that matter most here are:

- **Prompt injection through repository content** — content in an audited
  repository steering the agent into acting outside the declared scope, escaping
  the execution mode, or laundering an unverified claim into a verified finding.
- **Adapter and extension authority escape** — an adapter or community extension
  reaching network, filesystem, subprocess, or secret access it did not declare
  in its manifest.
- **Command or argument injection** in adapters that shell out to scanners.
- **Evidence integrity failures** — anything that lets an unverified candidate
  be reported as verified, or that lets a `BLOCKED` / `UNKNOWN` state be
  silently converted into `NOT_APPLICABLE`.
- **Release-gate bypass** — a path that returns `PASS` when required evidence is
  missing, defeating the fail-closed design.
- **Unsafe defaults** — a documented workflow that causes destructive, unbounded,
  or unauthorized testing when followed as written.
- **Secret or private-data leakage** through reports, logs, or rendered output.

### Out of scope

- Findings that SecHelix produced *about a third-party system.* Those belong to
  that system's owner, and disclosing them here would be the harm, not the fix.
- False positives and missed vulnerability classes. Those are correctness bugs —
  valuable, but report them as normal issues, not as security reports.
- Vulnerabilities in third-party scanners SecHelix can consume output from.
  Report those upstream.
- Anything requiring an attacker to already control the machine the agent runs on.

## Scope of the project

SecHelix is an application-security **methodology and skill bundle** for
authorized targets. It is not intended for unauthorized exploitation, credential
theft, persistence, malware deployment, denial of service, destructive payload
execution, or indiscriminate internet scanning.

## Safe defaults

SecHelix defaults to static and local evidence. Production testing should remain
non-destructive unless an operator explicitly authorizes a narrowly bounded
action in an environment they control.

## Supported versions

| Version | Supported |
|---|---|
| `3.0.0-alpha.x` | Yes — fixes land on `main` |
| `2.x` and earlier | No |

The project is pre-1.0 in API-stability terms despite the `3.x` version string:
the `3.x` line tracks the framework generation, not a stability guarantee. The
15 JSON contracts in `schemas/` are versioned individually; a breaking change to
any of them bumps that contract's version. Security fixes target `main` and the
most recent alpha only.

There are currently **no git tags and no published GitHub Releases**, so a
consumer cannot pin a verified artifact. Pin a commit SHA until tagged releases
exist.

## Dependency and supply-chain posture

Stated plainly, because a security tool should not overstate its own hygiene:

- the skill bundle and validators use the **Python standard library only** — no
  third-party runtime dependencies to audit;
- GitHub Actions are pinned to full commit SHAs, and workflow permissions are
  least-privilege;
- there is **no** CodeQL workflow, **no** Dependabot configuration, **no** SBOM,
  **no** OpenSSF Scorecard, and **no** signed release artifacts yet. Signed
  evidence manifests and trusted release provenance are on the
  [roadmap](ROADMAP.md), not shipped.

Future integrations that introduce packages, webhooks, hosted services, payment
widgets, or telemetry must be threat-modeled and documented before merge.
