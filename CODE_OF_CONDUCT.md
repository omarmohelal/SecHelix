# Code of Conduct

SecHelix is an evidence-first security project. Discussion should be rigorous
without becoming hostile.

## Scope

This applies to every project space: issues, pull requests, discussions, commit
and review comments, and any other channel the project operates. It also applies
when someone represents the project in public — a talk, a post, or a security
report filed on the project's behalf.

## Expected behavior

- Be respectful and specific.
- Challenge claims with evidence, not people.
- Treat uncertainty, refutation, and false positives as normal parts of security
  work. Being wrong in public about a finding is the process working, not a
  failure to be mocked.
- Protect private reports, secrets, credentials, customer data, and embargoed
  vulnerabilities.
- Keep dynamic testing inside systems you own or are explicitly authorized to test.

## Unacceptable behavior

- Harassment, discrimination, threats, or personal attacks.
- Publishing secrets, private customer data, or non-public vulnerability details
  without permission.
- Using project channels to coordinate unauthorized exploitation, destructive
  testing, credential theft, persistence, or denial of service.
- **Fabricating security results, CVEs, customer names, benchmark numbers, or
  trophy-case entries.** In a project whose entire thesis is that findings must
  be verified before they are asserted, fabricated evidence is the most serious
  violation on this list. It is treated as a level 3 or level 4 response on the
  first offence, not a warning.

## Reporting a violation

Report privately through a
**[private security advisory](https://github.com/omarmohelal/SecHelix/security/advisories/new)** —
the form is private to the maintainer and works for conduct reports as well as
vulnerabilities. Put `CONDUCT` in the title.

Reports are kept confidential. The reporter's identity is not shared with the
person reported without the reporter's consent.

**If your report concerns the maintainer**, or you do not want the maintainer to
see it, use
[GitHub's abuse reporting](https://github.com/contact/report-abuse) instead.
SecHelix has one maintainer, so there is no internal neutral party; GitHub is
the escalation path.

## Enforcement

Maintainers may edit, hide, or remove content that violates these rules.
Responses escalate:

1. **Correction** — a private note explaining what was wrong, no public record.
2. **Warning** — a stated consequence for continued behavior.
3. **Temporary restriction** — a bounded period with no interaction in project
   spaces.
4. **Permanent ban** — removal from all project spaces.

Severity, intent, and repetition determine the level. A single serious incident
can start at level 3 or 4.

## Appeals

Appeal by replying in the same private channel within 30 days, with the reason
you believe the response was wrong or disproportionate. Appeals are answered in
writing.

## Security reports

Do not open a public issue for a vulnerability in SecHelix itself if disclosure
would create risk. Follow [SECURITY.md](SECURITY.md).
